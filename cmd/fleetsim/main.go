// fleetsim: fleet-scale simulation and benchmark.
//
//	fleetsim -n 2000 -heartbeat 1s -out bench/results/DATE/sim.json
//
// Starts fleetd in-process on a real TCP port and N simulated devices (agent
// library in simulation mode: artifacts are downloaded and verified, health
// comes from the release's sim_health), each heartbeating on its own
// goroutine over HTTP. Then runs three scenarios, one after another:
//
//  1. good release, waves 1/10/50/100 %: time until every device runs it;
//  2. bad release (every trial fails): how many devices it reaches before
//     the canary gate halts the rollout, and that all of them rolled back;
//  3. flaky release (3 % failures, limit 10 %): completes; failures stay
//     on the previous version.
//
// Reports heartbeat throughput and latency percentiles, CPU and memory.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"edgefleet/internal/agent"
	"edgefleet/internal/proto"
	"edgefleet/internal/server"
	"edgefleet/internal/store"
)

const admin = "fleetsim-admin-token-000000000"

var (
	baseURL string
	relPriv ed25519.PrivateKey
)

func call(method, path string, body []byte, out any) int {
	req, _ := http.NewRequest(method, baseURL+path, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	} else {
		io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode
}

func release(ver string, size int, health string) {
	data := make([]byte, size)
	rand.Read(data)
	h := sha256.Sum256(data)
	m := &proto.Manifest{Version: ver, Size: int64(size), SHA256: hex.EncodeToString(h[:]), SimHealth: health}
	q := url.Values{"version": {ver}, "signature": {proto.SignManifest(relPriv, m)}, "sim_health": {health}}
	if c := call("POST", "/v1/admin/releases?"+q.Encode(), data, nil); c != 200 {
		log.Fatalf("release %s: %d", ver, c)
	}
}

type latencies struct {
	mu sync.Mutex
	v  []float64
}

func (l *latencies) add(d time.Duration) {
	l.mu.Lock()
	l.v = append(l.v, float64(d.Microseconds())/1000)
	l.mu.Unlock()
}

func (l *latencies) take() []float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := l.v
	l.v = nil
	sort.Float64s(v)
	return v
}

func pct(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return v[int(p*float64(len(v)-1))]
}

func cpuSeconds() float64 {
	b, _ := os.ReadFile("/proc/self/stat")
	f := strings.Fields(string(b)[strings.LastIndex(string(b), ")")+2:])
	ut, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	return (ut + st) / 100
}

func main() {
	n := flag.Int("n", 2000, "simulated devices")
	hb := flag.Duration("heartbeat", time.Second, "heartbeat interval")
	artifact := flag.Int("artifact-kb", 256, "artifact size")
	out := flag.String("out", "", "write results JSON here")
	flag.Parse()
	dir, _ := os.MkdirTemp("", "fleetsim")
	defer os.RemoveAll(dir)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	relPriv = priv
	srv, err := server.New(server.Config{DataDir: filepath.Join(dir, "cp"), AdminToken: admin, ReleaseKey: pub,
		HeartbeatSec: int(hb.Seconds() + 0.5), OfflineAfter: 5 * *hb, TickInterval: 200 * time.Millisecond})
	if err != nil {
		log.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	baseURL = "http://" + ln.Addr().String()
	go http.Serve(ln, srv.Handler())
	release("1.0", *artifact<<10, "ok")

	tr := &http.Transport{MaxIdleConns: *n + 10, MaxIdleConnsPerHost: *n + 10, IdleConnTimeout: time.Minute}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	var lat latencies
	agents := make([]*agent.Agent, *n)
	t0 := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i := range agents {
		var tok map[string]string
		call("POST", "/v1/admin/tokens", nil, &tok)
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, token string) {
			defer wg.Done()
			defer func() { <-sem }()
			a, err := agent.New(agent.Config{Server: baseURL, DeviceID: fmt.Sprintf("sim-%05d", i), StateDir: filepath.Join(dir, "dev", strconv.Itoa(i)),
				EnrollToken: token, Labels: map[string]string{"region": []string{"eu", "us", "ap"}[i%3]}, ReleaseKey: pub,
				InitialVersion: "1.0", Client: client, Seed: 1, Heartbeat: *hb})
			if err != nil {
				log.Fatal(err)
			}
			a.Start()
			agents[i] = a
		}(i, tok["token"])
	}
	wg.Wait()
	enroll := time.Since(t0)
	log.Printf("enrolled %d devices in %v", *n, enroll)
	ctx, cancel := context.WithCancel(context.Background())
	for i, a := range agents {
		go func(i int, a *agent.Agent) {
			time.Sleep(time.Duration(i) * *hb / time.Duration(*n)) // spread heartbeats
			for ctx.Err() == nil {
				s := time.Now()
				a.Beat()
				lat.add(time.Since(s))
				select {
				case <-ctx.Done():
				case <-time.After(*hb):
				}
			}
		}(i, a)
	}
	versions := func() map[string]int {
		m := map[string]int{}
		for _, a := range agents {
			m[a.BootState().ActiveVersion]++
		}
		return m
	}
	type scen struct {
		Name           string             `json:"name"`
		Seconds        float64            `json:"seconds"`
		FinalState     string             `json:"final_state"`
		Versions       map[string]int     `json:"versions"`
		Succeeded      int                `json:"succeeded"`
		Failed         int                `json:"failed"`
		DevicesReached int                `json:"devices_that_tried_it"`
		HeartbeatsPerS float64            `json:"heartbeats_per_sec"`
		LatencyMs      map[string]float64 `json:"heartbeat_latency_ms"`
		CPUCores       float64            `json:"cpu_cores"`
		Reason         string             `json:"reason,omitempty"`
	}
	run := func(name, ver, health string, waves []float64, maxFail float64, wantDone func(map[string]int) bool) scen {
		release(ver, *artifact<<10, health)
		var ws []map[string]float64
		for _, w := range waves {
			ws = append(ws, map[string]float64{"percent": w})
		}
		var ro store.Rollout
		if c := call("POST", "/v1/admin/rollouts", proto.MustJSON(map[string]any{"version": ver, "waves": ws, "max_failure_rate": maxFail,
			"min_report_fraction": 0.98}), &ro); c != 200 {
			log.Fatalf("rollout: %d", c)
		}
		hb0, cpu0, s := srv.Heartbeats.Load(), cpuSeconds(), time.Now()
		lat.take()
		var st struct {
			Rollout   store.Rollout `json:"rollout"`
			Succeeded int           `json:"succeeded"`
			Failed    int           `json:"failed"`
		}
		for {
			time.Sleep(200 * time.Millisecond)
			call("GET", "/v1/admin/rollouts/"+ro.ID, nil, &st)
			if (st.Rollout.State == store.Completed || st.Rollout.State == store.Halted) && wantDone(versions()) {
				break
			}
			if time.Since(s) > 10*time.Minute {
				log.Printf("%s: timed out", name)
				break
			}
		}
		el := time.Since(s).Seconds()
		l := lat.take()
		reached := 0
		for _, a := range agents {
			for _, f := range a.BootState().Failed {
				if f == ver {
					reached++
				}
			}
			if a.BootState().ActiveVersion == ver {
				reached++
			}
		}
		r := scen{Name: name, Seconds: el, FinalState: st.Rollout.State, Versions: versions(), Succeeded: st.Succeeded, Failed: st.Failed,
			DevicesReached: reached, HeartbeatsPerS: float64(srv.Heartbeats.Load()-hb0) / el,
			LatencyMs: map[string]float64{"p50": pct(l, .5), "p95": pct(l, .95), "p99": pct(l, .99), "max": pct(l, 1)},
			CPUCores:  (cpuSeconds() - cpu0) / el, Reason: st.Rollout.Reason}
		log.Printf("%s: %+v", name, r)
		return r
	}
	all := func(v string) func(map[string]int) bool { return func(m map[string]int) bool { return m[v] == *n } }
	res := []scen{
		run("good release", "2.0", "ok", []float64{1, 10, 50, 100}, 0.1, all("2.0")),
		run("bad release (all trials fail)", "3.0", "fail", []float64{1, 10, 50, 100}, 0.1, all("2.0")),
		run("flaky release (3% failures, 10% limit)", "4.0", "flaky:0.03", []float64{1, 10, 50, 100}, 0.1,
			func(m map[string]int) bool { return m["4.0"]+m["2.0"] == *n && m["4.0"] > 0 }),
	}
	cancel()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	jb := 0
	if fi, err := os.Stat(filepath.Join(dir, "cp", "state", "journal.log")); err == nil {
		jb = int(fi.Size())
	}
	result := map[string]any{"devices": *n, "heartbeat_interval_s": hb.Seconds(), "artifact_kb": *artifact,
		"enroll_seconds": enroll.Seconds(), "scenarios": res, "heap_mb": float64(ms.HeapAlloc) / 1e6,
		"journal_bytes": jb, "cpus": runtime.NumCPU(),
		"note": "control plane and all simulated devices share one process and the same 4 vCPUs"}
	b, _ := json.MarshalIndent(result, "", " ")
	fmt.Println(string(b))
	if *out != "" {
		os.MkdirAll(filepath.Dir(*out), 0o755)
		os.WriteFile(*out, b, 0o644)
	}
	srv.Close()
}
