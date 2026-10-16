package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"edgefleet/internal/proto"
)

// Key-rotation mode. The server pins the root key like the devices do, keeps
// the newest key set it has accepted in DataDir/keyset.json, serves it in
// every heartbeat reply, and accepts a release only if it is signed by a key
// in that set. The server checks the same rules as a device, but devices do
// not trust it: they verify the key set and the release themselves.

func (s *Server) keySetPath() string { return filepath.Join(s.cfg.DataDir, "keyset.json") }

func (s *Server) loadTrust() error {
	s.trust = &proto.Trust{Root: s.cfg.RootKey}
	now := s.cfg.Now()
	if b, err := os.ReadFile(s.keySetPath()); err == nil {
		var ks proto.SignedKeySet
		if err := json.Unmarshal(b, &ks); err != nil {
			return errors.New("keyset.json: " + err.Error())
		}
		// a stored set that has expired since is still the version floor
		if err := proto.VerifyKeySet(s.cfg.RootKey, &ks, now); err != nil && !errors.Is(err, proto.ErrKeySetExpired) {
			return errors.New("keyset.json: " + err.Error())
		}
		cp := ks
		s.trust.Current = &cp
	}
	if s.cfg.KeySet != nil {
		changed, err := s.trust.Accept(s.cfg.KeySet, now)
		if err != nil && !errors.Is(err, proto.ErrKeySetRollback) {
			return errors.New("initial key set: " + err.Error())
		}
		if changed {
			return s.saveKeySet(s.trust.Current)
		}
	}
	if s.trust.Current == nil {
		return errors.New("key-rotation mode needs an initial key set")
	}
	return nil
}

func (s *Server) saveKeySet(ks *proto.SignedKeySet) error {
	tmp := s.keySetPath() + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(proto.MustJSON(ks)); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Rename(tmp, s.keySetPath()); err != nil {
		return err
	}
	if d, err := os.Open(s.cfg.DataDir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func (s *Server) currentKeySet() *proto.SignedKeySet {
	if s.trust == nil {
		return nil
	}
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	return s.trust.Current
}

// PUT /v1/admin/keyset, body = SignedKeySet JSON. Rotation: a newer set
// signed by the root replaces the current one; older or conflicting sets
// are refused.
func (s *Server) putKeySet(w http.ResponseWriter, r *http.Request) {
	if s.trust == nil {
		errJSON(w, http.StatusConflict, "server is not in key-rotation mode (no root key)")
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	var ks proto.SignedKeySet
	if err != nil || json.Unmarshal(b, &ks) != nil {
		errJSON(w, http.StatusBadRequest, "bad key set")
		return
	}
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	prev := s.trust.Current
	changed, err := s.trust.Accept(&ks, s.cfg.Now())
	if err != nil {
		errJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if changed {
		if err := s.saveKeySet(s.trust.Current); err != nil {
			s.trust.Current = prev
			errJSON(w, http.StatusInternalServerError, "storage failure")
			return
		}
		log.Printf("key set rotated to version %d", ks.KeySet.Version)
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": s.trust.Current.KeySet.Version, "changed": changed})
}
