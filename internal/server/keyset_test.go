package server_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"edgefleet/internal/agent"
	"edgefleet/internal/proto"
	"edgefleet/internal/server"
)

type key struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKey(id string) key {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return key{id, pub, priv}
}

func (k key) entry() proto.ReleaseKey {
	return proto.ReleaseKey{ID: k.id, PublicKey: base64.StdEncoding.EncodeToString(k.pub)}
}

func manifest(ver string, content []byte) *proto.Manifest {
	h := sha256.Sum256(content)
	return &proto.Manifest{Version: ver, Size: int64(len(content)), SHA256: hex.EncodeToString(h[:]), SimHealth: "ok"}
}

// uploadWith signs the release with k and announces it as key id `as`.
func (f *fleet) uploadWith(ver string, k key, as string) int {
	content := []byte("#!/bin/sh\necho " + ver + "\n")
	sig := proto.SignManifest(k.priv, manifest(ver, content))
	q := url.Values{"version": {ver}, "signature": {sig}, "key_id": {as}, "sim_health": {"ok"}}
	return f.admin("POST", "/v1/admin/releases?"+q.Encode(), content, nil)
}

func (f *fleet) rollOut(ver string) {
	f.rollout(map[string]any{"version": ver, "waves": []map[string]float64{{"percent": 100}},
		"max_failure_rate": 0.5, "min_report_fraction": 1})
}

func (f *fleet) trustedVersions() []uint64 {
	var v []uint64
	for _, a := range f.agents {
		v = append(v, a.TrustedKeySetVersion())
	}
	return v
}

func (f *fleet) expect(ver string, ks uint64) {
	f.t.Helper()
	if got := f.versions(); got[ver] != len(f.agents) {
		f.t.Fatalf("want all devices on %s, got %v", ver, got)
	}
	for _, v := range f.trustedVersions() {
		if v != ks {
			f.t.Fatalf("want trusted key set %d, got %v", ks, f.trustedVersions())
		}
	}
}

func TestReleaseKeyRotationRevocationExpiryAndRollback(t *testing.T) {
	root, k1, k2, evil := newKey("root"), newKey("k1"), newKey("k2"), newKey("k1")
	now := time.Now()
	sign := func(ver uint64, exp time.Time, keys []key, revoked ...string) proto.SignedKeySet {
		ks := proto.KeySet{Version: ver, Expires: exp.Unix(), Revoked: revoked}
		for _, k := range keys {
			ks.Keys = append(ks.Keys, k.entry())
		}
		return proto.SignKeySet(root.priv, ks)
	}
	v1 := sign(1, now.Add(24*time.Hour), []key{k1})
	v2 := sign(2, now.Add(48*time.Hour), []key{k2}, "k1")
	v3 := sign(3, now.Add(96*time.Hour), []key{k2}, "k1")

	f := &fleet{t: t, dir: t.TempDir()}
	s, err := server.New(server.Config{DataDir: filepath.Join(f.dir, "server"), AdminToken: adminTok,
		RootKey: root.pub, KeySet: &v1, HeartbeatSec: 1, TickInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = s
	// the device API passes through `tamper` when it is set (a compromised
	// or misbehaving control plane)
	var tamper func(d *proto.Desired)
	inner := s.Handler()
	f.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tamper == nil || r.URL.Path != "/v1/heartbeat" {
			inner.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r)
		var d proto.Desired
		json.Unmarshal(rec.Body.Bytes(), &d)
		tamper(&d)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.Code)
		w.Write(proto.MustJSON(d))
	}))
	t.Cleanup(func() { f.http.Close(); f.srv.Close() })

	if code := f.uploadWith("1.0", k1, "k1"); code != 200 {
		t.Fatalf("1.0 upload: %d", code)
	}
	skew := time.Duration(0) // device clock offset
	for i := 0; i < 3; i++ {
		cfg := agent.Config{Server: f.http.URL, DeviceID: fmt.Sprintf("dev-%d", i), StateDir: filepath.Join(f.dir, "dev", fmt.Sprint(i)),
			EnrollToken: f.token(), RootKey: root.pub, InitialVersion: "1.0", Seed: 1,
			Now: func() time.Time { return time.Now().Add(skew) }}
		a, err := agent.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		a.Start()
		f.agents = append(f.agents, a)
		f.cfgs = append(f.cfgs, cfg)
	}
	t.Cleanup(func() {
		for _, a := range f.agents {
			a.Stop()
		}
	})
	rounds := func(n int) {
		for i := 0; i < n; i++ {
			f.round()
		}
	}

	// 1. key set v1 {k1}: devices learn it; a k1 release rolls out
	rounds(1)
	f.expect("1.0", 1)
	if code := f.uploadWith("2.0", evil, "k1"); code != 422 {
		t.Fatalf("release signed by an unknown key claiming id k1: %d", code)
	}
	if code := f.uploadWith("2.0", k2, "k2"); code != 422 {
		t.Fatalf("k2 release before k2 is authorised: %d", code)
	}
	if code := f.uploadWith("2.0", k1, "k1"); code != 200 {
		t.Fatalf("2.0: %d", code)
	}
	f.rollOut("2.0")
	rounds(6)
	f.expect("2.0", 1)

	// 2. rotate to v2 {k2}, k1 revoked
	put := func(ks proto.SignedKeySet) int { return f.admin("PUT", "/v1/admin/keyset", ks, nil) }
	if code := put(v2); code != 200 {
		t.Fatalf("PUT v2: %d", code)
	}
	if code := put(v1); code != 422 {
		t.Fatalf("PUT v1 after v2 (rollback): %d", code)
	}
	unrevoke := sign(3, now.Add(96*time.Hour), []key{k1, k2})
	if code := put(unrevoke); code != 422 {
		t.Fatalf("PUT key set that re-authorises revoked k1: %d", code)
	}
	forged := v3
	forged.KeySet.Keys = append(forged.KeySet.Keys, evil.entry())
	if code := put(forged); code != 422 {
		t.Fatalf("PUT modified key set: %d", code)
	}
	if code := f.uploadWith("3.0", k1, "k1"); code != 422 {
		t.Fatalf("release signed by revoked k1: %d", code)
	}
	if code := f.uploadWith("3.0", k2, "k2"); code != 200 {
		t.Fatalf("3.0: %d", code)
	}
	f.rollOut("3.0")
	rounds(6)
	f.expect("3.0", 2)

	// 3. a misbehaving server cannot get revoked keys or old key sets past
	//    the devices: it serves 4.0 re-signed with revoked k1 ...
	if code := f.uploadWith("4.0", k2, "k2"); code != 200 {
		t.Fatal(code)
	}
	f.rollOut("4.0")
	resign := func(d *proto.Desired) {
		if d.Manifest != nil {
			d.Signature, d.KeyID = proto.SignManifest(k1.priv, d.Manifest), "k1"
		}
	}
	tamper = resign
	rounds(4)
	f.expect("3.0", 2)
	// ... and also rolls the key set back to v1, which still lists k1
	tamper = func(d *proto.Desired) { resign(d); d.KeySet = &v1 }
	rounds(4)
	f.expect("3.0", 2)
	// ... or strips the key set and claims k2 with a k1 signature
	tamper = func(d *proto.Desired) {
		if d.Manifest != nil {
			d.Signature, d.KeyID = proto.SignManifest(k1.priv, d.Manifest), "k2"
		}
		d.KeySet = nil
	}
	rounds(4)
	f.expect("3.0", 2)
	// honest again: 4.0 installs
	tamper = nil
	rounds(6)
	f.expect("4.0", 2)

	// 4. key-set expiry, judged by the device's own clock: 49 h later the
	//    devices refuse v2 (expired) and install nothing ...
	skew = 49 * time.Hour
	if code := f.uploadWith("5.0", k2, "k2"); code != 200 {
		t.Fatal(code)
	}
	f.rollOut("5.0")
	rounds(4)
	f.expect("4.0", 2)
	// ... until the operator publishes a fresh v3
	if code := put(v3); code != 200 {
		t.Fatalf("PUT v3: %d", code)
	}
	rounds(6)
	f.expect("5.0", 3)

	// 5. the trusted key set survives an agent restart (version floor)
	for i, a := range f.agents {
		a.Stop()
		cfg := f.cfgs[i]
		cfg.EnrollToken = ""
		b, err := agent.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if b.TrustedKeySetVersion() != 3 {
			t.Fatalf("after restart: %d", b.TrustedKeySetVersion())
		}
		b.Start()
		f.agents[i] = b
	}
	// and the server keeps v3 across a restart even if started with v1
	f.srv.Close()
	s2, err := server.New(server.Config{DataDir: filepath.Join(f.dir, "server"), AdminToken: adminTok,
		RootKey: root.pub, KeySet: &v1, HeartbeatSec: 1, TickInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = s2
	inner = s2.Handler()
	var cur map[string]any
	b := bytes.NewBuffer(proto.MustJSON(v3))
	req, _ := http.NewRequest("PUT", f.http.URL+"/v1/admin/keyset", b)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&cur)
	resp.Body.Close()
	if cur["version"] != float64(3) || cur["changed"] != false {
		t.Fatalf("server after restart: %v", cur)
	}
}
