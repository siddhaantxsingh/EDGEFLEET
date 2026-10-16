// Package server is the fleet control plane (fleetd).
package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"edgefleet/internal/proto"
	"edgefleet/internal/rollout"
	"edgefleet/internal/store"
)

// Config for the control plane.
type Config struct {
	DataDir    string
	AdminToken string
	ReleaseKey ed25519.PublicKey // only releases signed by this key are accepted
	// Key-rotation mode (used instead of ReleaseKey when RootKey is set):
	// releases must be signed by a key in the current root-signed key set.
	RootKey      ed25519.PublicKey
	KeySet       *proto.SignedKeySet // initial key set; a newer one saved in DataDir wins
	HeartbeatSec int
	OfflineAfter time.Duration
	TickInterval time.Duration
	MaxArtifact  int64
	Now          func() time.Time
}

type soft struct {
	lastSeen time.Time
	state    string
	target   string
	lastErr  string
	metrics  map[string]float64
}

// Server implements the HTTP API.
type Server struct {
	cfg     Config
	st      *store.Store
	softMu  sync.Mutex
	softs   map[string]*soft
	nonceMu sync.Mutex
	nonces  map[string]int64 // deviceID|nonce -> ts
	trustMu sync.Mutex
	trust   *proto.Trust // nil unless key-rotation mode
	stop    chan struct{}
	wg      sync.WaitGroup

	Heartbeats, AuthFailures, Enrollments, ArtifactBytes atomic.Uint64
}

var (
	idRE      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	versionRE = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,64}$`)
)

// New opens the store and starts the rollout controller.
func New(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HeartbeatSec == 0 {
		cfg.HeartbeatSec = 30
	}
	if cfg.OfflineAfter == 0 {
		cfg.OfflineAfter = 3 * time.Duration(cfg.HeartbeatSec) * time.Second
	}
	if cfg.TickInterval == 0 {
		cfg.TickInterval = time.Second
	}
	if cfg.MaxArtifact == 0 {
		cfg.MaxArtifact = 512 << 20
	}
	if len(cfg.AdminToken) < 16 {
		return nil, errors.New("admin token must be at least 16 characters")
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state"))
	if err != nil {
		return nil, err
	}
	os.MkdirAll(filepath.Join(cfg.DataDir, "artifacts"), 0o755)
	s := &Server{cfg: cfg, st: st, softs: map[string]*soft{}, nonces: map[string]int64{}, stop: make(chan struct{})}
	if cfg.RootKey != nil {
		if err := s.loadTrust(); err != nil {
			st.Close()
			return nil, err
		}
	}
	s.wg.Add(1)
	go s.controller()
	return s, nil
}

// Close stops the controller and closes the store.
func (s *Server) Close() {
	close(s.stop)
	s.wg.Wait()
	s.st.Mu.Lock()
	s.st.Compact()
	s.st.Mu.Unlock()
	s.st.Close()
}

// Store exposes the state (tests and benchmarks).
func (s *Server) Store() *store.Store { return s.st }

func (s *Server) now() int64 { return s.cfg.Now().UnixMilli() }

// Handler returns the HTTP API.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/enroll", s.enroll)
	m.HandleFunc("POST /v1/heartbeat", s.heartbeat)
	m.HandleFunc("GET /v1/artifacts/{version}", s.artifact)
	m.HandleFunc("POST /v1/admin/tokens", s.admin(s.newToken))
	m.HandleFunc("POST /v1/admin/releases", s.admin(s.newRelease))
	m.HandleFunc("PUT /v1/admin/keyset", s.admin(s.putKeySet))
	m.HandleFunc("POST /v1/admin/rollouts", s.admin(s.newRollout))
	m.HandleFunc("GET /v1/admin/rollouts/{id}", s.admin(s.getRollout))
	m.HandleFunc("POST /v1/admin/rollouts/{id}/{action}", s.admin(s.rolloutAction))
	m.HandleFunc("GET /v1/admin/devices", s.admin(s.listDevices))
	m.HandleFunc("GET /metrics", s.metrics)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	return m
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AdminToken)) != 1 {
			errJSON(w, http.StatusUnauthorized, "admin token required")
			return
		}
		h(w, r)
	}
}

// ------------------------------------------------------------- device API

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if !idRE.MatchString(req.DeviceID) {
		errJSON(w, http.StatusUnprocessableEntity, "invalid device_id")
		return
	}
	if _, err := proto.DecodePublicKey(req.PublicKey); err != nil {
		errJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if req.Version != "" && !versionRE.MatchString(req.Version) {
		errJSON(w, http.StatusUnprocessableEntity, "invalid version")
		return
	}
	if len(req.Labels) > 32 {
		errJSON(w, http.StatusUnprocessableEntity, "too many labels")
		return
	}
	s.st.Mu.Lock()
	defer s.st.Mu.Unlock()
	if !s.st.S.Tokens[req.Token] {
		s.AuthFailures.Add(1)
		errJSON(w, http.StatusForbidden, "unknown or already used enrollment token")
		return
	}
	if _, exists := s.st.S.Devices[req.DeviceID]; exists {
		errJSON(w, http.StatusConflict, "device id already enrolled")
		return
	}
	d := &store.Device{ID: req.DeviceID, PublicKey: req.PublicKey, Labels: req.Labels, Version: req.Version, Enrolled: s.now()}
	if err := s.st.Append(store.Event{Token: req.Token, Enroll: d}, s.now()); err != nil {
		errJSON(w, http.StatusInternalServerError, "store failure")
		return
	}
	s.Enrollments.Add(1)
	writeJSON(w, http.StatusOK, map[string]any{"heartbeat_sec": s.cfg.HeartbeatSec})
}

func (s *Server) authDevice(w http.ResponseWriter, r *http.Request, body []byte) (string, bool) {
	id, err := proto.VerifyRequest(r, body, s.cfg.Now(), s.lookupKey, s.seenNonce)
	if err != nil {
		s.AuthFailures.Add(1)
		errJSON(w, http.StatusUnauthorized, err.Error())
		return "", false
	}
	return id, true
}

func (s *Server) lookupKey(id string) (ed25519.PublicKey, bool) {
	s.st.Mu.Lock()
	d, ok := s.st.S.Devices[id]
	s.st.Mu.Unlock()
	if !ok {
		return nil, false
	}
	k, err := proto.DecodePublicKey(d.PublicKey)
	return k, err == nil
}

func (s *Server) seenNonce(id, nonce string, ts int64) bool {
	k := id + "|" + nonce
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	if _, ok := s.nonces[k]; ok {
		return true
	}
	s.nonces[k] = ts
	if len(s.nonces) > 200000 {
		cut := s.now() - proto.MaxSkew.Milliseconds()
		for k, t := range s.nonces {
			if t < cut {
				delete(s.nonces, k)
			}
		}
	}
	return false
}

func (s *Server) currentRollout() *store.Rollout {
	o := s.st.S.Order
	if len(o) == 0 {
		return nil
	}
	return s.st.S.Rollouts[o[len(o)-1]]
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		errJSON(w, http.StatusBadRequest, "body too large")
		return
	}
	id, ok := s.authDevice(w, r, body)
	if !ok {
		return
	}
	var hb proto.Heartbeat
	if err := json.Unmarshal(body, &hb); err != nil || hb.DeviceID != id {
		errJSON(w, http.StatusBadRequest, "bad heartbeat")
		return
	}
	s.Heartbeats.Add(1)
	s.softMu.Lock()
	sf := s.softs[id]
	if sf == nil {
		sf = &soft{}
		s.softs[id] = sf
	}
	sf.lastSeen, sf.state, sf.target, sf.lastErr, sf.metrics = s.cfg.Now(), hb.State, hb.TargetVersion, hb.LastError, hb.Metrics
	s.softMu.Unlock()

	s.st.Mu.Lock()
	defer s.st.Mu.Unlock()
	d := s.st.S.Devices[id]
	now := s.now()
	if hb.ActiveVersion != d.Version && versionRE.MatchString(hb.ActiveVersion) {
		if err := s.st.Append(store.Event{Version: &store.VersionEvt{Device: id, Version: hb.ActiveVersion}}, now); err != nil {
			errJSON(w, http.StatusInternalServerError, "store failure")
			return
		}
	}
	ro := s.currentRollout()
	if hb.Result != nil && ro != nil && hb.Result.Version == ro.Version {
		if _, done := ro.Results[id]; !done {
			if err := s.st.Append(store.Event{Result: &store.ResultEvt{Rollout: ro.ID, Device: id, Success: hb.Result.Success}}, now); err != nil {
				errJSON(w, http.StatusInternalServerError, "store failure")
				return
			}
		}
	}
	resp := proto.Desired{HeartbeatSec: s.cfg.HeartbeatSec, KeySet: s.currentKeySet()}
	if want := rollout.Desired(ro, d); want != "" && want != d.Version {
		if rel := s.st.S.Releases[want]; rel != nil {
			resp.Version = want
			resp.Manifest = &proto.Manifest{Version: rel.Version, Size: rel.Size, SHA256: rel.SHA256, SimHealth: rel.SimHealth}
			resp.Signature = rel.Signature
			resp.KeyID = rel.KeyID
			resp.ArtifactURL = "/v1/artifacts/" + rel.Version
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) artifact(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authDevice(w, r, nil); !ok {
		return
	}
	s.st.Mu.Lock()
	rel := s.st.S.Releases[r.PathValue("version")]
	s.st.Mu.Unlock()
	if rel == nil {
		errJSON(w, http.StatusNotFound, "no such release")
		return
	}
	f, err := os.Open(rel.Path)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "artifact missing")
		return
	}
	defer f.Close()
	cw := &countWriter{ResponseWriter: w}
	http.ServeContent(cw, r, "", time.UnixMilli(rel.Created), f) // supports Range: resumable downloads
	s.ArtifactBytes.Add(uint64(cw.n))
}

type countWriter struct {
	http.ResponseWriter
	n int
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += n
	return n, err
}

// -------------------------------------------------------------- admin API

func (s *Server) newToken(w http.ResponseWriter, r *http.Request) {
	var b [16]byte
	rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	s.st.Mu.Lock()
	err := s.st.Append(store.Event{Token: tok}, s.now())
	s.st.Mu.Unlock()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "store failure")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// POST /v1/admin/releases?version=V&signature=B64&sim_health=H, body = artifact bytes.
func (s *Server) newRelease(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ver := q.Get("version")
	if !versionRE.MatchString(ver) {
		errJSON(w, http.StatusUnprocessableEntity, "invalid version")
		return
	}
	tmp, err := os.CreateTemp(filepath.Join(s.cfg.DataDir, "artifacts"), "upload-*")
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "storage failure")
		return
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), http.MaxBytesReader(w, r.Body, s.cfg.MaxArtifact))
	if err != nil || n == 0 {
		tmp.Close()
		errJSON(w, http.StatusBadRequest, "artifact upload failed or empty")
		return
	}
	tmp.Sync()
	tmp.Close()
	m := &proto.Manifest{Version: ver, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), SimHealth: q.Get("sim_health")}
	if s.trust != nil {
		s.trustMu.Lock()
		err := s.trust.VerifyRelease(m, q.Get("signature"), q.Get("key_id"), s.cfg.Now())
		s.trustMu.Unlock()
		if err != nil {
			errJSON(w, http.StatusUnprocessableEntity, "release signature rejected: "+err.Error())
			return
		}
	} else if err := proto.VerifyManifest(s.cfg.ReleaseKey, m, q.Get("signature")); err != nil {
		errJSON(w, http.StatusUnprocessableEntity, "release signature does not verify with the configured release key")
		return
	}
	final := filepath.Join(s.cfg.DataDir, "artifacts", ver+".bin")
	s.st.Mu.Lock()
	defer s.st.Mu.Unlock()
	if _, ok := s.st.S.Releases[ver]; ok {
		errJSON(w, http.StatusConflict, "version already exists (releases are immutable)")
		return
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		errJSON(w, http.StatusInternalServerError, "storage failure")
		return
	}
	rel := &store.Release{Version: ver, Size: n, SHA256: m.SHA256, Signature: q.Get("signature"), KeyID: q.Get("key_id"), SimHealth: m.SimHealth, Path: final, Created: s.now()}
	if err := s.st.Append(store.Event{Release: rel}, s.now()); err != nil {
		errJSON(w, http.StatusInternalServerError, "store failure")
		return
	}
	writeJSON(w, http.StatusOK, rel)
}

func (s *Server) newRollout(w http.ResponseWriter, r *http.Request) {
	var ro store.Rollout
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&ro); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if ro.MinReportFraction == 0 {
		ro.MinReportFraction = 1
	}
	if err := rollout.Validate(&ro); err != nil {
		errJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.st.Mu.Lock()
	defer s.st.Mu.Unlock()
	if s.st.S.Releases[ro.Version] == nil {
		errJSON(w, http.StatusUnprocessableEntity, "unknown release")
		return
	}
	if cur := s.currentRollout(); cur != nil && (cur.State == store.Running || cur.State == store.Paused) {
		errJSON(w, http.StatusConflict, "rollout "+cur.ID+" is still active")
		return
	}
	if ro.FromVersion == "" {
		// the most common current version among the selected devices
		count := map[string]int{}
		for _, d := range s.st.S.Devices {
			if rollout.Selected(&ro, d) && d.Version != "" {
				count[d.Version]++
			}
		}
		best := 0
		for v, c := range count {
			if c > best || (c == best && v < ro.FromVersion) {
				ro.FromVersion, best = v, c
			}
		}
	}
	// a halt or abort must be able to put devices back: require an artifact
	if ro.FromVersion == "" || s.st.S.Releases[ro.FromVersion] == nil || ro.FromVersion == ro.Version {
		errJSON(w, http.StatusUnprocessableEntity, fmt.Sprintf("no release to roll back to (from_version %q); upload it or set from_version", ro.FromVersion))
		return
	}
	var b [6]byte
	rand.Read(b[:])
	ro.ID = "ro-" + hex.EncodeToString(b[:])
	ro.State, ro.Wave, ro.WaveStarted, ro.Created = store.Running, 0, s.now(), s.now()
	ro.Results = nil
	if err := s.st.Append(store.Event{Rollout: &ro}, s.now()); err != nil {
		errJSON(w, http.StatusInternalServerError, "store failure")
		return
	}
	writeJSON(w, http.StatusOK, s.st.S.Rollouts[ro.ID])
}

func (s *Server) online(id string) bool {
	s.softMu.Lock()
	defer s.softMu.Unlock()
	sf := s.softs[id]
	return sf != nil && s.cfg.Now().Sub(sf.lastSeen) < s.cfg.OfflineAfter
}

func (s *Server) devices() []*store.Device {
	ds := make([]*store.Device, 0, len(s.st.S.Devices))
	for _, d := range s.st.S.Devices {
		ds = append(ds, d)
	}
	return ds
}

func (s *Server) getRollout(w http.ResponseWriter, r *http.Request) {
	s.st.Mu.Lock()
	defer s.st.Mu.Unlock()
	ro := s.st.S.Rollouts[r.PathValue("id")]
	if ro == nil {
		errJSON(w, http.StatusNotFound, "no such rollout")
		return
	}
	g := rollout.Evaluate(ro, s.devices(), s.now(), s.online)
	on := 0
	for _, d := range s.st.S.Devices {
		if d.Version == ro.Version {
			on++
		}
	}
	ok, failed := 0, 0
	for _, v := range ro.Results {
		if v {
			ok++
		} else {
			failed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rollout": ro, "gate": g, "devices_on_version": on,
		"succeeded": ok, "failed": failed, "fleet_size": len(s.st.S.Devices)})
}

func (s *Server) rolloutAction(w http.ResponseWriter, r *http.Request) {
	s.st.Mu.Lock()
	defer s.st.Mu.Unlock()
	ro := s.st.S.Rollouts[r.PathValue("id")]
	if ro == nil {
		errJSON(w, http.StatusNotFound, "no such rollout")
		return
	}
	next := *ro
	switch r.PathValue("action") {
	case "pause":
		if ro.State != store.Running {
			errJSON(w, http.StatusConflict, "not running")
			return
		}
		next.State = store.Paused
	case "resume":
		if ro.State != store.Paused {
			errJSON(w, http.StatusConflict, "not paused")
			return
		}
		next.State = store.Running
	case "abort":
		if ro.State != store.Running && ro.State != store.Paused {
			errJSON(w, http.StatusConflict, "not active")
			return
		}
		next.State, next.Reason = store.Aborted, "aborted by operator"
	default:
		errJSON(w, http.StatusNotFound, "unknown action")
		return
	}
	if err := s.st.Append(store.Event{Rollout: &next}, s.now()); err != nil {
		errJSON(w, http.StatusInternalServerError, "store failure")
		return
	}
	writeJSON(w, http.StatusOK, s.st.S.Rollouts[ro.ID])
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	s.st.Mu.Lock()
	ds := s.devices()
	s.st.Mu.Unlock()
	sort.Slice(ds, func(i, j int) bool { return ds[i].ID < ds[j].ID })
	out := make([]map[string]any, 0, len(ds))
	s.softMu.Lock()
	for _, d := range ds {
		e := map[string]any{"id": d.ID, "version": d.Version, "labels": d.Labels}
		if sf := s.softs[d.ID]; sf != nil {
			e["state"], e["last_seen"], e["online"], e["last_error"] = sf.state, sf.lastSeen.UnixMilli(),
				s.cfg.Now().Sub(sf.lastSeen) < s.cfg.OfflineAfter, sf.lastErr
		}
		out = append(out, e)
	}
	s.softMu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	s.st.Mu.Lock()
	n := len(s.st.S.Devices)
	versions := map[string]int{}
	for _, d := range s.st.S.Devices {
		versions[d.Version]++
	}
	ro := s.currentRollout()
	s.st.Mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "fleet_devices %d\nfleet_heartbeats_total %d\nfleet_auth_failures_total %d\nfleet_enrollments_total %d\nfleet_artifact_bytes_total %d\n",
		n, s.Heartbeats.Load(), s.AuthFailures.Load(), s.Enrollments.Load(), s.ArtifactBytes.Load())
	for v, c := range versions {
		fmt.Fprintf(&b, "fleet_devices_by_version{version=%q} %d\n", v, c)
	}
	if ro != nil {
		fmt.Fprintf(&b, "fleet_rollout_wave{id=%q,state=%q} %d\n", ro.ID, ro.State, ro.Wave)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(b.String()))
}

// ------------------------------------------------------------- controller

func (s *Server) controller() {
	defer s.wg.Done()
	tk := time.NewTicker(s.cfg.TickInterval)
	defer tk.Stop()
	compactEvery := 0
	for {
		select {
		case <-s.stop:
			return
		case <-tk.C:
		}
		s.Tick()
		if compactEvery++; compactEvery%600 == 0 {
			s.st.Mu.Lock()
			if err := s.st.Compact(); err != nil {
				log.Printf("compact: %v", err)
			}
			s.st.Mu.Unlock()
		}
	}
}

// Tick evaluates the active rollout once (exported for tests).
func (s *Server) Tick() {
	s.st.Mu.Lock()
	defer s.st.Mu.Unlock()
	ro := s.currentRollout()
	if ro == nil || ro.State != store.Running {
		return
	}
	g := rollout.Evaluate(ro, s.devices(), s.now(), s.online)
	next := *ro
	switch g.Action {
	case "advance":
		next.Wave++
		next.WaveStarted = s.now()
	case "complete":
		next.State = store.Completed
	case "halt":
		next.State = store.Halted
		next.Reason = g.Reason
	default:
		return
	}
	if err := s.st.Append(store.Event{Rollout: &next}, s.now()); err != nil {
		log.Printf("rollout transition: %v", err)
		return
	}
	log.Printf("rollout %s: %s -> wave %d state %s %s", ro.ID, g.Action, next.Wave, next.State, next.Reason)
}
