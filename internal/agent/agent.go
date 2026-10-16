// Package agent is the on-device update agent.
//
// Disk layout under StateDir:
//
//	key            Ed25519 private key (created at enrollment, 0600)
//	slots/a/app    slots/b/app       A/B application slots
//	boot.json      {active slot, active version, trial, pending result}
//
// boot.json is the only mutable state and is replaced atomically (write
// temp, fsync, rename, fsync dir). The update procedure keeps the device
// bootable after a crash or power loss at any step:
//
//  1. download into the INACTIVE slot (resumable via HTTP Range, file
//     app.part), verify SHA-256 and the release signature (pinned key),
//     rename to app;
//  2. write trial = {slot, version, attempts: 0} - the active slot is
//     untouched;
//  3. "boot" the trial: increment and persist attempts, then start the new
//     app and run the health check;
//  4. healthy -> active = trial slot, trial = nil, pending result success;
//     unhealthy -> trial = nil (the old slot stays active), restart the old
//     app, pending result failure (rolled back).
//
// On start-up, a trial with attempts >= MaxBootAttempts means the agent
// crashed repeatedly while trialling: it rolls back (like a bootloader's
// boot counter). The pending result stays in boot.json until a heartbeat
// carrying it is accepted by the server.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"edgefleet/internal/proto"
)

// MaxBootAttempts before an unfinished trial is rolled back at start-up.
const MaxBootAttempts = 2

// Config configures an agent.
type Config struct {
	Server      string
	DeviceID    string
	StateDir    string
	EnrollToken string
	Labels      map[string]string
	ReleaseKey  ed25519.PublicKey
	// RootKey enables key-rotation mode: releases must be signed by a key in
	// a root-signed key set (proto/keyset.go) instead of ReleaseKey.
	RootKey        ed25519.PublicKey
	Now            func() time.Time // clock for key-set expiry (default time.Now)
	InitialVersion string           // version shipped in slot a at manufacturing
	// Exec runs the app from the slot (real devices); otherwise the health
	// outcome comes from the manifest's SimHealth (fleet simulation).
	Exec         bool
	HealthWindow time.Duration // how long the new app must stay up
	Client       *http.Client
	Seed         int64         // for flaky simulated health
	Heartbeat    time.Duration // override the server's interval (simulation)
	// test hook: called at named points of the update procedure
	Hook func(point string)
}

// Boot is the persistent boot state.
type Boot struct {
	Active        string              `json:"active"` // "a" or "b"
	ActiveVersion string              `json:"active_version"`
	Trial         *Trial              `json:"trial,omitempty"`
	Pending       *proto.UpdateResult `json:"pending,omitempty"`
	// versions that failed their trial on this device: never retried
	Failed []string `json:"failed,omitempty"`
}

// Trial is an installed but not yet committed version.
type Trial struct {
	Slot     string `json:"slot"`
	Version  string `json:"version"`
	Attempts int    `json:"attempts"`
}

// Agent is one device.
type Agent struct {
	cfg     Config
	key     ed25519.PrivateKey
	boot    Boot
	state   string
	lastErr string
	target  string
	app     *exec.Cmd
	appDone chan struct{}
	mu      sync.Mutex
	hbSec   int
	trust   *proto.Trust
}

func (a *Agent) failed(v string) bool {
	for _, f := range a.boot.Failed {
		if f == v {
			return true
		}
	}
	return false
}

func (a *Agent) markFailed(v string) {
	if !a.failed(v) {
		a.boot.Failed = append(a.boot.Failed, v)
	}
}

func (a *Agent) hook(p string) {
	if a.cfg.Hook != nil {
		a.cfg.Hook(p)
	}
}

// New loads (or initialises) the device state and enrolls if needed.
func New(cfg Config) (*Agent, error) {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.HealthWindow == 0 {
		cfg.HealthWindow = 2 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &Agent{cfg: cfg, state: "idle", hbSec: 30}
	if cfg.RootKey != nil {
		a.trust = &proto.Trust{Root: cfg.RootKey}
		if b, err := os.ReadFile(filepath.Join(cfg.StateDir, "keyset.json")); err == nil {
			var ks proto.SignedKeySet
			if err := json.Unmarshal(b, &ks); err != nil {
				return nil, fmt.Errorf("agent: keyset.json: %w", err)
			}
			// it was verified when accepted; re-check the signature (not the
			// expiry: an expired set still sets the version floor)
			if err := proto.VerifyKeySet(cfg.RootKey, &ks, time.Unix(0, 0)); err != nil {
				return nil, fmt.Errorf("agent: keyset.json: %w", err)
			}
			a.trust.Current = &ks
		}
	}
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "slots", "a"), 0o755); err != nil {
		return nil, err
	}
	os.MkdirAll(filepath.Join(cfg.StateDir, "slots", "b"), 0o755)
	kp := filepath.Join(cfg.StateDir, "key")
	if b, err := os.ReadFile(kp); err == nil {
		if len(b) != ed25519.PrivateKeySize {
			return nil, errors.New("agent: corrupt key file")
		}
		a.key = ed25519.PrivateKey(b)
	} else {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := cfg.enroll(priv); err != nil {
			return nil, err
		}
		if err := atomicWrite(kp, priv, 0o600); err != nil {
			return nil, err
		}
		a.key = priv
	}
	bp := filepath.Join(cfg.StateDir, "boot.json")
	if b, err := os.ReadFile(bp); err == nil {
		if err := json.Unmarshal(b, &a.boot); err != nil {
			return nil, fmt.Errorf("agent: boot.json: %w", err)
		}
	} else {
		a.boot = Boot{Active: "a", ActiveVersion: cfg.InitialVersion}
		if err := a.saveBoot(); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (c Config) enroll(priv ed25519.PrivateKey) error {
	body := proto.MustJSON(proto.EnrollRequest{Token: c.EnrollToken, DeviceID: c.DeviceID,
		PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), Labels: c.Labels, Version: c.InitialVersion})
	resp, err := c.Client.Post(c.Server+"/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enroll: %s: %s", resp.Status, b)
	}
	return nil
}

func atomicWrite(p string, b []byte, mode os.FileMode) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(p)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func (a *Agent) saveBoot() error {
	return atomicWrite(filepath.Join(a.cfg.StateDir, "boot.json"), proto.MustJSON(a.boot), 0o644)
}

// BootState returns a copy of the persistent state.
func (a *Agent) BootState() Boot {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.boot
	return b
}

func other(slot string) string {
	if slot == "a" {
		return "b"
	}
	return "a"
}

// Start performs the boot sequence: resolve an unfinished trial, then start
// the active application.
func (a *Agent) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if t := a.boot.Trial; t != nil {
		if t.Attempts >= MaxBootAttempts {
			a.boot.Pending = &proto.UpdateResult{Version: t.Version, Success: false, RolledBack: true,
				Reason: fmt.Sprintf("trial boot did not complete after %d attempts", t.Attempts)}
			a.markFailed(t.Version)
			a.boot.Trial = nil
			if err := a.saveBoot(); err != nil {
				return err
			}
		} else {
			// resume the trial (another boot attempt)
			return a.trialLocked()
		}
	}
	a.startApp(a.boot.Active)
	return nil
}

func (a *Agent) appPath(slot string) string {
	return filepath.Join(a.cfg.StateDir, "slots", slot, "app")
}

func (a *Agent) startApp(slot string) {
	if !a.cfg.Exec {
		return
	}
	a.stopApp()
	cmd := exec.Command(a.appPath(slot), "run")
	cmd.Dir = filepath.Dir(a.appPath(slot))
	if err := cmd.Start(); err != nil {
		a.lastErr = "start app: " + err.Error()
		return
	}
	a.app = cmd
	done := make(chan struct{})
	a.appDone = done
	go func() { cmd.Wait(); close(done) }()
}

func (a *Agent) stopApp() {
	if a.app != nil && a.app.Process != nil {
		a.app.Process.Kill()
		<-a.appDone
		a.app = nil
	}
}

// Stop stops the managed application.
func (a *Agent) Stop() {
	a.mu.Lock()
	a.stopApp()
	a.mu.Unlock()
}

// healthy decides whether the trial version works.
func (a *Agent) healthy(slot string, m *proto.Manifest) (bool, string) {
	if !a.cfg.Exec {
		switch {
		case m.SimHealth == "" || m.SimHealth == "ok":
			return true, ""
		case m.SimHealth == "fail":
			return false, "simulated health check failure"
		case strings.HasPrefix(m.SimHealth, "flaky:"):
			p, _ := strconv.ParseFloat(strings.TrimPrefix(m.SimHealth, "flaky:"), 64)
			h := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d", a.cfg.DeviceID, m.Version, a.cfg.Seed)))
			x := new(big.Int).SetBytes(h[:8])
			if float64(x.Uint64()>>11)/float64(uint64(1)<<53) < p {
				return false, "simulated flaky failure"
			}
			return true, ""
		}
		return false, "unknown sim_health " + m.SimHealth
	}
	// real app: it must stay up for HealthWindow and `app health` must pass
	if a.app == nil {
		return false, "application failed to start: " + a.lastErr
	}
	select {
	case <-a.appDone:
		return false, "application exited during the health window"
	case <-time.After(a.cfg.HealthWindow):
	}
	out, err := exec.Command(a.appPath(slot), "health").CombinedOutput()
	if err != nil {
		return false, "health check failed: " + strings.TrimSpace(string(out))
	}
	return true, ""
}

// trialLocked boots the trial slot and commits or rolls back. Caller holds mu.
func (a *Agent) trialLocked() error {
	t := a.boot.Trial
	t.Attempts++
	if err := a.saveBoot(); err != nil {
		return err
	}
	a.hook("trial-booting")
	a.state = "trial"
	m, err := a.readManifest(t.Slot)
	if err != nil {
		return a.finishTrial(false, "installed manifest unreadable: "+err.Error())
	}
	a.startApp(t.Slot)
	ok, reason := a.healthy(t.Slot, m)
	a.hook("trial-checked")
	return a.finishTrial(ok, reason)
}

func (a *Agent) finishTrial(ok bool, reason string) error {
	t := a.boot.Trial
	if ok {
		a.boot.Active, a.boot.ActiveVersion = t.Slot, t.Version
		a.boot.Pending = &proto.UpdateResult{Version: t.Version, Success: true}
	} else {
		a.boot.Pending = &proto.UpdateResult{Version: t.Version, Success: false, Reason: reason, RolledBack: true}
		a.markFailed(t.Version)
		a.lastErr = reason
		a.startApp(a.boot.Active) // back to the known-good slot
	}
	a.boot.Trial = nil
	a.state = "idle"
	return a.saveBoot()
}

func (a *Agent) readManifest(slot string) (*proto.Manifest, error) {
	b, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "slots", slot, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m proto.Manifest
	return &m, json.Unmarshal(b, &m)
}

// ------------------------------------------------------------- networking

func (a *Agent) do(method, path string, body []byte, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, a.cfg.Server+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	proto.SignRequest(req, a.cfg.DeviceID, a.key, body, time.Now())
	return a.cfg.Client.Do(req)
}

// Beat sends one heartbeat and acts on the answer. It returns the server's
// heartbeat interval.
func (a *Agent) Beat() (time.Duration, error) {
	a.mu.Lock()
	hb := proto.Heartbeat{DeviceID: a.cfg.DeviceID, ActiveVersion: a.boot.ActiveVersion, State: a.state,
		TargetVersion: a.target, LastError: a.lastErr, Result: a.boot.Pending}
	a.mu.Unlock()
	resp, err := a.do("POST", "/v1/heartbeat", proto.MustJSON(hb), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("heartbeat: %s: %s", resp.Status, b)
	}
	var d proto.Desired
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return 0, err
	}
	a.mu.Lock()
	if hb.Result != nil && a.boot.Pending == hb.Result {
		a.boot.Pending = nil // the server has it
		a.saveBoot()
	}
	if d.HeartbeatSec > 0 {
		a.hbSec = d.HeartbeatSec
	}
	a.mu.Unlock()
	if err := a.acceptKeySet(d.KeySet); err != nil {
		a.mu.Lock()
		a.lastErr = err.Error()
		a.mu.Unlock()
		return a.interval(), err
	}
	if d.Version != "" && d.Version != hb.ActiveVersion && d.Manifest != nil {
		if err := a.update(&d); err != nil {
			a.mu.Lock()
			a.lastErr = err.Error()
			a.state = "idle"
			a.mu.Unlock()
			return a.interval(), err
		}
	}
	return a.interval(), nil
}

func (a *Agent) interval() time.Duration {
	if a.cfg.Heartbeat > 0 {
		return a.cfg.Heartbeat
	}
	return time.Duration(a.hbSec) * time.Second
}

// ErrVerify reports a release that failed signature or digest verification.
var ErrVerify = errors.New("release verification failed")

func (a *Agent) update(d *proto.Desired) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := d.Manifest
	if m.Version != d.Version {
		return fmt.Errorf("%w: manifest version mismatch", ErrVerify)
	}
	if a.trust != nil {
		if err := a.trust.VerifyRelease(m, d.Signature, d.KeyID, a.cfg.Now()); err != nil {
			return fmt.Errorf("%w: %v", ErrVerify, err)
		}
	} else if err := proto.VerifyManifest(a.cfg.ReleaseKey, m, d.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	if a.failed(m.Version) {
		return nil // already failed on this device: do not retry
	}
	a.target = m.Version
	slot := other(a.boot.Active)
	dir := filepath.Join(a.cfg.StateDir, "slots", slot)
	// reuse the inactive slot if it already holds this exact release (rollback)
	if old, err := a.readManifest(slot); err == nil && old.SHA256 == m.SHA256 && fileHash(filepath.Join(dir, "app")) == m.SHA256 {
		a.hook("slot-reused")
	} else {
		a.state = "downloading"
		os.Remove(filepath.Join(dir, "manifest.json"))
		if err := a.download(d.ArtifactURL, filepath.Join(dir, "app.part"), m.Size); err != nil {
			return err
		}
		a.hook("downloaded")
		if fileHash(filepath.Join(dir, "app.part")) != m.SHA256 {
			os.Remove(filepath.Join(dir, "app.part"))
			return fmt.Errorf("%w: SHA-256 mismatch", ErrVerify)
		}
		os.Chmod(filepath.Join(dir, "app.part"), 0o755)
		if err := os.Rename(filepath.Join(dir, "app.part"), filepath.Join(dir, "app")); err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(dir, "manifest.json"), proto.MustJSON(m), 0o644); err != nil {
			return err
		}
	}
	a.state = "installing"
	a.boot.Trial = &Trial{Slot: slot, Version: m.Version}
	if err := a.saveBoot(); err != nil {
		return err
	}
	a.hook("installed")
	return a.trialLocked()
}

// acceptKeySet applies a key set from the server (key-rotation mode). A
// rejected set (bad signature, expired, older version) is an error and the
// trusted set stays as it was; it is saved before it is used.
func (a *Agent) acceptKeySet(ks *proto.SignedKeySet) error {
	if a.trust == nil || ks == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.trust.Current
	changed, err := a.trust.Accept(ks, a.cfg.Now())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	if changed {
		if err := atomicWrite(filepath.Join(a.cfg.StateDir, "keyset.json"), proto.MustJSON(a.trust.Current), 0o644); err != nil {
			a.trust.Current = prev
			return err
		}
		a.hook("keyset-accepted")
	}
	return nil
}

// TrustedKeySetVersion is the version of the key set the device trusts (0 if none).
func (a *Agent) TrustedKeySetVersion() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.trust == nil || a.trust.Current == nil {
		return 0
	}
	return a.trust.Current.KeySet.Version
}

func fileHash(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

// download fetches url into path, resuming from an existing partial file.
func (a *Agent) download(url, path string, size int64) error {
	var have int64
	if fi, err := os.Stat(path); err == nil {
		have = fi.Size()
		if have > size {
			os.Remove(path)
			have = 0
		}
	}
	if have == size {
		return nil
	}
	hdr := map[string]string{}
	if have > 0 {
		hdr["Range"] = fmt.Sprintf("bytes=%d-", have)
	}
	resp, err := a.do("GET", url, nil, hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	flags := os.O_CREATE | os.O_WRONLY
	switch resp.StatusCode {
	case http.StatusPartialContent:
		flags |= os.O_APPEND
	case http.StatusOK:
		flags |= os.O_TRUNC
		have = 0
	default:
		return fmt.Errorf("download: %s", resp.Status)
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, io.LimitReader(resp.Body, size-have)); err != nil {
		f.Sync()
		return fmt.Errorf("download interrupted: %w", err)
	}
	return f.Sync()
}

// Run heartbeats until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) {
	for {
		iv, err := a.Beat()
		if err != nil || iv == 0 {
			iv = a.interval()
			if iv == 0 {
				iv = time.Second
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		}
	}
}
