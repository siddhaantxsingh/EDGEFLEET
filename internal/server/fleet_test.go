package server_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"edgefleet/internal/agent"
	"edgefleet/internal/proto"
	"edgefleet/internal/server"
	"edgefleet/internal/store"
)

const adminTok = "test-admin-token-0123456789"

type fleet struct {
	t       *testing.T
	dir     string
	srv     *server.Server
	http    *httptest.Server
	relPub  ed25519.PublicKey
	relPriv ed25519.PrivateKey
	agents  []*agent.Agent
	cfgs    []agent.Config
}

func newFleet(t *testing.T, n int) *fleet {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fleet{t: t, dir: t.TempDir(), relPub: pub, relPriv: priv}
	f.startServer()
	f.release("1.0", []byte("#!/bin/sh\necho v1\n"), "ok")
	for i := 0; i < n; i++ {
		f.addAgent(fmt.Sprintf("dev-%04d", i), map[string]string{"site": []string{"north", "south"}[i%2]})
	}
	return f
}

func (f *fleet) startServer() {
	s, err := server.New(server.Config{DataDir: filepath.Join(f.dir, "server"), AdminToken: adminTok, ReleaseKey: f.relPub,
		HeartbeatSec: 1, TickInterval: time.Hour})
	if err != nil {
		f.t.Fatal(err)
	}
	f.srv = s
	if f.http == nil {
		f.http = httptest.NewServer(s.Handler())
		f.t.Cleanup(func() { f.http.Close(); f.srv.Close() })
	} else {
		f.http.Config.Handler = s.Handler()
	}
}

func (f *fleet) admin(method, path string, body any, out any) int {
	var rd io.Reader
	if b, ok := body.([]byte); ok {
		rd = bytes.NewReader(b)
	} else if body != nil {
		rd = bytes.NewReader(proto.MustJSON(body))
	}
	req, _ := http.NewRequest(method, f.http.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func (f *fleet) release(ver string, content []byte, health string) {
	h := sha256.Sum256(content)
	m := &proto.Manifest{Version: ver, Size: int64(len(content)), SHA256: hex.EncodeToString(h[:]), SimHealth: health}
	sig := proto.SignManifest(f.relPriv, m)
	q := url.Values{"version": {ver}, "signature": {sig}, "sim_health": {health}}
	if code := f.admin("POST", "/v1/admin/releases?"+q.Encode(), content, nil); code != 200 {
		f.t.Fatalf("release %s: %d", ver, code)
	}
}

func (f *fleet) token() string {
	var out map[string]string
	f.admin("POST", "/v1/admin/tokens", nil, &out)
	return out["token"]
}

func (f *fleet) addAgent(id string, labels map[string]string) {
	cfg := agent.Config{Server: f.http.URL, DeviceID: id, StateDir: filepath.Join(f.dir, "dev", id), EnrollToken: f.token(),
		Labels: labels, ReleaseKey: f.relPub, InitialVersion: "1.0", Seed: 1}
	a, err := agent.New(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	a.Start()
	f.agents = append(f.agents, a)
	f.cfgs = append(f.cfgs, cfg)
}

// round: every agent heartbeats once (concurrently), then the controller ticks.
func (f *fleet) round() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for _, a := range f.agents {
		wg.Add(1)
		sem <- struct{}{}
		go func(a *agent.Agent) {
			defer wg.Done()
			a.Beat()
			<-sem
		}(a)
	}
	wg.Wait()
	f.srv.Tick()
}

type status struct {
	Rollout   store.Rollout `json:"rollout"`
	OnVersion int           `json:"devices_on_version"`
	Succeeded int           `json:"succeeded"`
	Failed    int           `json:"failed"`
}

func (f *fleet) rollout(spec map[string]any) string {
	var r store.Rollout
	if code := f.admin("POST", "/v1/admin/rollouts", spec, &r); code != 200 {
		f.t.Fatalf("create rollout: %d", code)
	}
	return r.ID
}

func (f *fleet) status(id string) status {
	var s status
	f.admin("GET", "/v1/admin/rollouts/"+id, nil, &s)
	return s
}

func (f *fleet) versions() map[string]int {
	out := map[string]int{}
	for _, a := range f.agents {
		out[a.BootState().ActiveVersion]++
	}
	return out
}

func waves() []map[string]float64 {
	return []map[string]float64{{"percent": 5}, {"percent": 25}, {"percent": 100}}
}

func TestGoodRolloutCompletesInWaves(t *testing.T) {
	f := newFleet(t, 120)
	f.release("2.0", []byte("#!/bin/sh\necho v2\n"), "ok")
	id := f.rollout(map[string]any{"version": "2.0", "waves": waves(), "max_failure_rate": 0.1, "min_report_fraction": 1})
	maxSeen := map[int]int{}
	for i := 0; i < 20; i++ {
		f.round()
		st := f.status(id)
		if st.OnVersion > maxSeen[st.Rollout.Wave] {
			maxSeen[st.Rollout.Wave] = st.OnVersion
		}
		if st.Rollout.State == store.Completed {
			break
		}
	}
	st := f.status(id)
	if st.Rollout.State != store.Completed || f.versions()["2.0"] != 120 || st.Failed != 0 {
		t.Fatalf("rollout %s, versions %v", st.Rollout.State, f.versions())
	}
	// wave 0 (5 %) never had more than ~15 % of the fleet updated
	if maxSeen[0] > 18 {
		t.Fatalf("wave 0 updated %d devices", maxSeen[0])
	}
}

func TestBadReleaseHaltsAtCanaryAndRollsBack(t *testing.T) {
	f := newFleet(t, 200)
	f.release("3.0", []byte("#!/bin/sh\nexit 1\n"), "fail")
	id := f.rollout(map[string]any{"version": "3.0", "waves": waves(), "max_failure_rate": 0.2, "min_report_fraction": 1})
	for i := 0; i < 10; i++ {
		f.round()
	}
	st := f.status(id)
	if st.Rollout.State != store.Halted || st.Rollout.Wave != 0 {
		t.Fatalf("expected halt in wave 0, got %s wave %d", st.Rollout.State, st.Rollout.Wave)
	}
	if v := f.versions(); v["1.0"] != 200 {
		t.Fatalf("devices left on the bad version: %v", v)
	}
	touched := 0
	for _, a := range f.agents {
		if len(a.BootState().Failed) > 0 {
			touched++
		}
	}
	if touched == 0 || touched > 20 {
		t.Fatalf("%d devices tried the bad release (only the ~5%% canary wave should)", touched)
	}
	t.Logf("bad release reached %d of 200 devices before the halt", touched)
}

func TestFlakyReleaseUnderThresholdCompletesFailuresStayRolledBack(t *testing.T) {
	f := newFleet(t, 200)
	f.release("2.1", []byte("v2.1"), "flaky:0.05")
	id := f.rollout(map[string]any{"version": "2.1", "waves": waves(), "max_failure_rate": 0.25, "min_report_fraction": 1})
	for i := 0; i < 20 && f.status(id).Rollout.State == store.Running; i++ {
		f.round()
	}
	st := f.status(id)
	v := f.versions()
	if st.Rollout.State != store.Completed || st.Failed == 0 || v["1.0"] != st.Failed || v["2.1"]+v["1.0"] != 200 {
		t.Fatalf("state %s failed %d versions %v", st.Rollout.State, st.Failed, v)
	}
}

func TestOperatorAbortRollsBackUpdatedDevices(t *testing.T) {
	f := newFleet(t, 60)
	f.release("2.0", []byte("v2"), "ok")
	id := f.rollout(map[string]any{"version": "2.0", "waves": []map[string]float64{{"percent": 50}, {"percent": 100}},
		"max_failure_rate": 0.1, "min_report_fraction": 1, "bake_ms": 3600000})
	f.round()
	f.round()
	if f.versions()["2.0"] == 0 {
		t.Fatal("first wave did not update")
	}
	if code := f.admin("POST", "/v1/admin/rollouts/"+id+"/abort", nil, nil); code != 200 {
		t.Fatal("abort failed")
	}
	f.round()
	f.round()
	if v := f.versions(); v["1.0"] != 60 {
		t.Fatalf("abort did not roll back: %v", v)
	}
}

func TestTamperedArtifactAndUnsignedReleaseRejected(t *testing.T) {
	f := newFleet(t, 3)
	// an upload whose signature does not match is refused by the server
	q := url.Values{"version": {"9.9"}, "signature": {proto.SignManifest(f.relPriv, &proto.Manifest{Version: "9.9"})}}
	if code := f.admin("POST", "/v1/admin/releases?"+q.Encode(), []byte("evil"), nil); code != 422 {
		t.Fatalf("unsigned release accepted: %d", code)
	}
	// a correctly signed release whose stored bytes are modified afterwards
	f.release("2.0", []byte("good bytes"), "ok")
	os.WriteFile(filepath.Join(f.dir, "server", "artifacts", "2.0.bin"), []byte("evil bytes"), 0o644)
	f.rollout(map[string]any{"version": "2.0", "waves": []map[string]float64{{"percent": 100}}, "max_failure_rate": 0, "min_report_fraction": 1})
	for _, a := range f.agents {
		if _, err := a.Beat(); !errors.Is(err, agent.ErrVerify) {
			t.Fatalf("tampered artifact not rejected: %v", err)
		}
	}
	if v := f.versions(); v["1.0"] != 3 {
		t.Fatalf("tampered artifact installed: %v", v)
	}
}

func TestEnrollmentTokensAreSingleUseAndAdminIsProtected(t *testing.T) {
	f := newFleet(t, 1)
	tok := f.token()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := func(id string) []byte {
		return proto.MustJSON(proto.EnrollRequest{Token: tok, DeviceID: id, PublicKey: encodeKey(pub)})
	}
	post := func(b []byte) int {
		r, _ := http.Post(f.http.URL+"/v1/enroll", "application/json", bytes.NewReader(b))
		r.Body.Close()
		return r.StatusCode
	}
	if post(body("x1")) != 200 || post(body("x2")) != 403 {
		t.Fatal("token reuse allowed")
	}
	r, _ := http.Post(f.http.URL+"/v1/admin/tokens", "", nil)
	if r.StatusCode != 401 {
		t.Fatal("admin API without token")
	}
	r, _ = http.Post(f.http.URL+"/v1/heartbeat", "application/json", bytes.NewReader([]byte(`{"device_id":"dev-0000"}`)))
	if r.StatusCode != 401 {
		t.Fatal("unsigned heartbeat accepted")
	}
}

func encodeKey(k ed25519.PublicKey) string {
	return base64Std(k)
}

// Crash the agent at each step of the update procedure, "reboot" it from
// its persisted state, and check it always has a valid active version and
// converges to the target.
func TestAgentCrashAtEveryUpdateStepRecovers(t *testing.T) {
	for _, point := range []string{"downloaded", "installed", "trial-booting", "trial-checked"} {
		t.Run(point, func(t *testing.T) {
			f := newFleet(t, 1)
			f.release("2.0", []byte("v2 payload"), "ok")
			f.rollout(map[string]any{"version": "2.0", "waves": []map[string]float64{{"percent": 100}}, "max_failure_rate": 0, "min_report_fraction": 1})
			cfg := f.cfgs[0]
			crashed := false
			cfg.Hook = func(p string) {
				if p == point && !crashed {
					crashed = true
					panic("power loss at " + p)
				}
			}
			a := mustAgent(t, cfg)
			func() {
				defer func() { recover() }()
				a.Beat()
			}()
			if !crashed {
				t.Fatal("hook not reached")
			}
			// reboot from disk
			cfg.Hook = nil
			b := mustAgent(t, cfg)
			if err := b.Start(); err != nil {
				t.Fatal(err)
			}
			bs := b.BootState()
			if bs.ActiveVersion != "1.0" && bs.ActiveVersion != "2.0" {
				t.Fatalf("invalid active version %q after crash", bs.ActiveVersion)
			}
			for i := 0; i < 5 && b.BootState().ActiveVersion != "2.0"; i++ {
				b.Beat()
			}
			if v := b.BootState().ActiveVersion; v != "2.0" {
				t.Fatalf("did not converge after crash at %s: %v", point, b.BootState())
			}
		})
	}
}

func TestCrashLoopDuringTrialRollsBackViaBootCounter(t *testing.T) {
	f := newFleet(t, 1)
	f.release("2.0", []byte("v2"), "ok")
	f.rollout(map[string]any{"version": "2.0", "waves": []map[string]float64{{"percent": 100}}, "max_failure_rate": 1, "min_report_fraction": 1})
	cfg := f.cfgs[0]
	cfg.Hook = func(p string) {
		if p == "trial-booting" {
			panic("new version hangs the device")
		}
	}
	a := mustAgent(t, cfg)
	func() { defer func() { recover() }(); a.Beat() }()
	for boot := 0; boot < agent.MaxBootAttempts; boot++ {
		b := mustAgent(t, cfg)
		func() { defer func() { recover() }(); b.Start() }()
	}
	cfg.Hook = nil
	b := mustAgent(t, cfg)
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	bs := b.BootState()
	if bs.ActiveVersion != "1.0" || bs.Trial != nil || bs.Pending == nil || bs.Pending.Success || !bs.Pending.RolledBack {
		t.Fatalf("boot counter did not roll back: %+v", bs)
	}
	b.Beat() // reports the failure, does not retry
	if b.BootState().ActiveVersion != "1.0" || b.BootState().Pending != nil {
		t.Fatalf("after report: %+v", b.BootState())
	}
}

func TestResumedDownloadUsesRange(t *testing.T) {
	f := newFleet(t, 1)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64<<10) // 1 MiB
	f.release("2.0", payload, "ok")
	f.rollout(map[string]any{"version": "2.0", "waves": []map[string]float64{{"percent": 100}}, "max_failure_rate": 0, "min_report_fraction": 1})
	// half of the artifact is already on disk from an interrupted download
	part := filepath.Join(f.cfgs[0].StateDir, "slots", "b", "app.part")
	os.WriteFile(part, payload[:len(payload)/2], 0o644)
	f.agents[0].Beat()
	if v := f.agents[0].BootState().ActiveVersion; v != "2.0" {
		t.Fatalf("not updated: %s", v)
	}
	if got := f.srv.ArtifactBytes.Load(); got != uint64(len(payload)/2) {
		t.Fatalf("server sent %d bytes, expected only the missing half (%d)", got, len(payload)/2)
	}
}

func TestControlPlaneRestartKeepsRolloutState(t *testing.T) {
	f := newFleet(t, 80)
	f.release("2.0", []byte("v2"), "ok")
	id := f.rollout(map[string]any{"version": "2.0", "waves": waves(), "max_failure_rate": 0.1, "min_report_fraction": 1})
	f.round()
	f.round()
	before := f.status(id)
	f.srv.Close()
	f.startServer()
	after := f.status(id)
	if after.Rollout.Wave != before.Rollout.Wave || after.Succeeded != before.Succeeded || after.Rollout.State != before.Rollout.State {
		t.Fatalf("state changed across restart: %+v -> %+v", before, after)
	}
	for i := 0; i < 20 && f.status(id).Rollout.State == store.Running; i++ {
		f.round()
	}
	if f.status(id).Rollout.State != store.Completed || f.versions()["2.0"] != 80 {
		t.Fatalf("rollout did not finish after restart: %v", f.versions())
	}
}

func mustAgent(t *testing.T, cfg agent.Config) *agent.Agent {
	a, err := agent.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
