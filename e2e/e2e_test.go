// End-to-end: real fleetd, fleet-agent and fleetctl binaries; artifacts are
// executable shell scripts that the agents really run and health-check.
package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var bin string

func TestMain(m *testing.M) {
	bin, _ = os.MkdirTemp("", "fleetbin")
	for _, c := range []string{"fleetd", "fleet-agent", "fleetctl"} {
		if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, c), "../cmd/"+c).CombinedOutput(); err != nil {
			fmt.Println(string(out))
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(bin)
	os.Exit(code)
}

// app writes "<version> <pid>" to ../../running when started, then sleeps;
// `app health` succeeds. A "bad" app exits immediately.
func app(version string, bad bool) []byte {
	run := `echo "` + version + ` $$" > ../../running; exec sleep 1000`
	if bad {
		run = `echo "` + version + ` $$" > ../../running; exit 1`
	}
	return []byte("#!/bin/sh\ncase \"$1\" in\nrun) " + run + " ;;\nhealth) exit 0 ;;\nesac\n")
}

type env struct {
	t      *testing.T
	dir    string
	url    string
	env    []string
	procs  []*exec.Cmd
	pubkey string
}

func (e *env) ctl(args ...string) string {
	cmd := exec.Command(filepath.Join(bin, "fleetctl"), args...)
	cmd.Env = e.env
	cmd.Dir = e.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("fleetctl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (e *env) start(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(filepath.Join(bin, name), args...)
	cmd.Env = e.env
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	e.procs = append(e.procs, cmd)
	return cmd
}

func freePort(t *testing.T) int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func running(dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "running"))
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return ""
	}
	// the recorded process must still be alive
	if err := exec.Command("kill", "-0", f[1]).Run(); err != nil {
		return f[0] + " (dead)"
	}
	return f[0]
}

func TestRealAgentsUpdateRollBackAndSurviveRestart(t *testing.T) {
	e := &env{t: t, dir: t.TempDir()}
	port := freePort(t)
	e.url = fmt.Sprintf("http://127.0.0.1:%d", port)
	e.env = append(os.Environ(), "FLEET_SERVER="+e.url, "FLEET_ADMIN_TOKEN=e2e-admin-token-0123456789")
	defer func() {
		for _, p := range e.procs {
			p.Process.Kill()
			p.Wait()
		}
		exec.Command("pkill", "-f", "sleep 1000").Run()
	}()
	e.pubkey = strings.TrimSpace(e.ctl("keygen", "-out", filepath.Join(e.dir, "release.key")))
	e.start("fleetd", "-data", filepath.Join(e.dir, "cp"), "-listen", fmt.Sprintf("127.0.0.1:%d", port),
		"-release-pubkey", e.pubkey, "-heartbeat-sec", "1", "-tick", "100ms")
	for i := 0; i < 50; i++ {
		if r, err := http.Get(e.url + "/healthz"); err == nil {
			r.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for v, bad := range map[string]bool{"1.0": false, "2.0": false, "3.0": true} {
		p := filepath.Join(e.dir, "app-"+v)
		os.WriteFile(p, app(v, bad), 0o755)
		e.ctl("release", "-key", filepath.Join(e.dir, "release.key"), "-version", v, "-file", p)
	}
	devs := []string{"d1", "d2", "d3"}
	startAgent := func(d string, token string) {
		e.start("fleet-agent", "-server", e.url, "-id", d, "-state", filepath.Join(e.dir, d), "-token", token,
			"-release-pubkey", e.pubkey, "-initial-version", "1.0", "-exec", "-health-window", "700ms", "-heartbeat", "200ms")
	}
	agents := map[string]*exec.Cmd{}
	for _, d := range devs {
		// manufacturing: slot a holds version 1.0
		os.MkdirAll(filepath.Join(e.dir, d, "slots", "a"), 0o755)
		os.WriteFile(filepath.Join(e.dir, d, "slots", "a", "app"), app("1.0", false), 0o755)
		var tok map[string]string
		json.Unmarshal([]byte(e.ctl("token")), &tok)
		startAgent(d, tok["token"])
		agents[d] = e.procs[len(e.procs)-1]
	}
	wait := func(what string, cond func() bool) {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out: %s (running: %s %s %s)", what, running(filepath.Join(e.dir, "d1")), running(filepath.Join(e.dir, "d2")), running(filepath.Join(e.dir, "d3")))
	}
	all := func(v string) func() bool {
		return func() bool {
			for _, d := range devs {
				if running(filepath.Join(e.dir, d)) != v {
					return false
				}
			}
			return true
		}
	}
	wait("all devices run 1.0", all("1.0"))

	var ro struct{ ID string }
	json.Unmarshal([]byte(e.ctl("rollout", "-version", "2.0", "-waves", "34,100", "-max-failure", "0", "-min-report", "1")), &ro)
	wait("all devices run 2.0", all("2.0"))
	state := func(id string) string {
		var st struct{ Rollout struct{ State string } }
		cmd := exec.Command(filepath.Join(bin, "fleetctl"), "status", id)
		cmd.Env = e.env
		out, _ := cmd.Output()
		json.Unmarshal(out, &st)
		return st.Rollout.State
	}
	wait("rollout 2.0 completed", func() bool { return state(ro.ID) == "completed" })

	// a release that crashes on start: the canary rolls back and the rollout halts
	json.Unmarshal([]byte(e.ctl("rollout", "-version", "3.0", "-waves", "34,100", "-max-failure", "0", "-min-report", "1")), &ro)
	wait("rollout 3.0 halted", func() bool { return state(ro.ID) == "halted" })
	time.Sleep(time.Second)
	wait("every device back on a live 2.0 process", all("2.0"))

	// restart an agent (process crash): it comes back on the committed version
	agents["d2"].Process.Kill()
	agents["d2"].Wait()
	exec.Command("pkill", "-f", "sleep 1000").Run() // the device "reboots": its app dies too
	startAgent("d2", "")
	wait("d2 back on 2.0 after restart", func() bool { return running(filepath.Join(e.dir, "d2")) == "2.0" })
}

// ctlErr runs fleetctl and returns its output and whether it succeeded.
func (e *env) ctlErr(args ...string) (string, bool) {
	cmd := exec.Command(filepath.Join(bin, "fleetctl"), args...)
	cmd.Env = e.env
	cmd.Dir = e.dir
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// Key rotation with the real binaries: root key pinned on devices, release
// keys rotated through a root-signed key set, the old key revoked.
func TestKeyRotationWithRealBinaries(t *testing.T) {
	e := &env{t: t, dir: t.TempDir()}
	port := freePort(t)
	e.url = fmt.Sprintf("http://127.0.0.1:%d", port)
	e.env = append(os.Environ(), "FLEET_SERVER="+e.url, "FLEET_ADMIN_TOKEN=e2e-admin-token-0123456789")
	defer func() {
		for _, p := range e.procs {
			p.Process.Kill()
			p.Wait()
		}
		exec.Command("pkill", "-f", "sleep 1000").Run()
	}()
	p := func(n string) string { return filepath.Join(e.dir, n) }
	root := strings.TrimSpace(e.ctl("keygen", "-out", p("root.key")))
	relA := strings.TrimSpace(e.ctl("keygen", "-out", p("rel-a.key")))
	relB := strings.TrimSpace(e.ctl("keygen", "-out", p("rel-b.key")))
	e.ctl("keyset", "-root", p("root.key"), "-set-version", "1", "-ttl", "1h", "-keys", "rel-a="+relA, "-out", p("ks1.json"))
	e.start("fleetd", "-data", p("cp"), "-listen", fmt.Sprintf("127.0.0.1:%d", port),
		"-root-pubkey", root, "-keyset", p("ks1.json"), "-heartbeat-sec", "1", "-tick", "100ms")
	for i := 0; i < 50; i++ {
		if r, err := http.Get(e.url + "/healthz"); err == nil {
			r.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	release := func(v, key, id string) bool {
		os.WriteFile(p("app-"+v), app(v, false), 0o755)
		_, ok := e.ctlErr("release", "-key", p(key), "-key-id", id, "-version", v, "-file", p("app-"+v))
		return ok
	}
	for _, v := range []string{"1.0", "2.0"} {
		if !release(v, "rel-a.key", "rel-a") {
			t.Fatalf("release %s with rel-a refused", v)
		}
	}
	devs := []string{"k1", "k2"}
	for _, d := range devs {
		os.MkdirAll(filepath.Join(e.dir, d, "slots", "a"), 0o755)
		os.WriteFile(filepath.Join(e.dir, d, "slots", "a", "app"), app("1.0", false), 0o755)
		var tok map[string]string
		json.Unmarshal([]byte(e.ctl("token")), &tok)
		e.start("fleet-agent", "-server", e.url, "-id", d, "-state", filepath.Join(e.dir, d), "-token", tok["token"],
			"-root-pubkey", root, "-initial-version", "1.0", "-exec", "-health-window", "700ms", "-heartbeat", "200ms")
	}
	wait := func(what string, cond func() bool) {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out: %s", what)
	}
	all := func(v string) func() bool {
		return func() bool {
			for _, d := range devs {
				if running(filepath.Join(e.dir, d)) != v {
					return false
				}
			}
			return true
		}
	}
	trusted := func(ver float64) func() bool {
		return func() bool {
			for _, d := range devs {
				var ks struct {
					KeySet struct{ Version float64 } `json:"key_set"`
				}
				b, _ := os.ReadFile(filepath.Join(e.dir, d, "keyset.json"))
				if json.Unmarshal(b, &ks) != nil || ks.KeySet.Version != ver {
					return false
				}
			}
			return true
		}
	}
	state := func(id string) string {
		var st struct{ Rollout struct{ State string } }
		out, _ := e.ctlErr("status", id)
		json.Unmarshal([]byte(out), &st)
		return st.Rollout.State
	}
	var ro struct{ ID string }
	wait("all devices run 1.0", all("1.0"))
	json.Unmarshal([]byte(e.ctl("rollout", "-version", "2.0", "-waves", "100", "-max-failure", "0", "-min-report", "1")), &ro)
	wait("all devices run 2.0 (signed by rel-a)", all("2.0"))
	wait("rollout 2.0 completed", func() bool { return state(ro.ID) == "completed" })
	wait("devices trust key set 1", trusted(1))

	// rotate: v2 authorises rel-b and revokes rel-a
	e.ctl("keyset", "-root", p("root.key"), "-set-version", "2", "-ttl", "1h", "-keys", "rel-b="+relB, "-revoke", "rel-a", "-out", p("ks2.json"))
	e.ctl("keyset-push", "-file", p("ks2.json"))
	if out, ok := e.ctlErr("keyset-push", "-file", p("ks1.json")); ok || !strings.Contains(out, "older") {
		t.Fatalf("pushing the old key set again: ok=%v %s", ok, out)
	}
	if release("3.0", "rel-a.key", "rel-a") {
		t.Fatal("release signed by revoked rel-a accepted")
	}
	if !release("3.0", "rel-b.key", "rel-b") {
		t.Fatal("release signed by rel-b refused")
	}
	json.Unmarshal([]byte(e.ctl("rollout", "-version", "3.0", "-waves", "100", "-max-failure", "0", "-min-report", "1")), &ro)
	wait("all devices run 3.0 (signed by rel-b)", all("3.0"))
	wait("rollout 3.0 completed", func() bool { return state(ro.ID) == "completed" })
	wait("devices trust key set 2", trusted(2))
}
