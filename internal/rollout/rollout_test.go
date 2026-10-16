package rollout

import (
	"fmt"
	"math"
	"testing"

	"edgefleet/internal/store"
)

func fleet(n int) []*store.Device {
	out := make([]*store.Device, n)
	for i := range out {
		out[i] = &store.Device{ID: fmt.Sprintf("dev-%05d", i), Version: "1.0", Labels: map[string]string{"site": []string{"a", "b"}[i%2]}}
	}
	return out
}

func ro() *store.Rollout {
	return &store.Rollout{ID: "r1", Version: "2.0", FromVersion: "1.0", Waves: []store.Wave{{Percent: 1}, {Percent: 10}, {Percent: 50}, {Percent: 100}},
		MaxFailureRate: 0.2, MinReportFraction: 0.9, State: store.Running, Results: map[string]bool{}}
}

func TestWaveSizesAreProportionalAndDeterministic(t *testing.T) {
	r := ro()
	ds := fleet(20000)
	counts := make([]int, 4)
	for _, d := range ds {
		w := WaveOf(r, d.ID)
		if w < 0 {
			t.Fatal("device outside every wave although the last wave is 100%")
		}
		counts[w]++
		if WaveOf(r, d.ID) != w {
			t.Fatal("non-deterministic membership")
		}
	}
	want := []float64{0.01, 0.09, 0.40, 0.50}
	for i, c := range counts {
		frac := float64(c) / float64(len(ds))
		if math.Abs(frac-want[i]) > 4*math.Sqrt(want[i]*(1-want[i])/float64(len(ds))) {
			t.Fatalf("wave %d has %.4f of devices, want %.2f", i, frac, want[i])
		}
	}
	// a different rollout picks different canaries
	r2 := ro()
	r2.ID = "r2"
	same := 0
	for _, d := range ds {
		if WaveOf(r, d.ID) == 0 && WaveOf(r2, d.ID) == 0 {
			same++
		}
	}
	if same > counts[0]/5 {
		t.Fatalf("canary sets overlap too much: %d of %d", same, counts[0])
	}
}

func TestDesiredFollowsWavesStatesAndFailures(t *testing.T) {
	r := ro()
	ds := fleet(2000)
	var w0, w2 *store.Device
	for _, d := range ds {
		switch WaveOf(r, d.ID) {
		case 0:
			w0 = d
		case 2:
			w2 = d
		}
	}
	if Desired(r, w0) != "2.0" || Desired(r, w2) != "" {
		t.Fatal("only wave-0 devices should be targeted in wave 0")
	}
	r.Results[w0.ID] = false
	if Desired(r, w0) != "" {
		t.Fatal("a device that failed must not be retried")
	}
	r.State = store.Halted
	w0.Version = "2.0"
	if Desired(r, w0) != "1.0" || Desired(r, w2) != "" {
		t.Fatal("halted rollouts roll updated devices back, and leave the rest alone")
	}
	r.State = store.Running
	r.Selector = map[string]string{"site": "zzz"}
	if Desired(r, w0) != "" {
		t.Fatal("selector ignored")
	}
}

func TestGateHaltsOnFailuresAndWaitsForReports(t *testing.T) {
	r := ro()
	ds := fleet(5000)
	var members []*store.Device
	for _, d := range ds {
		if WaveOf(r, d.ID) == 0 {
			members = append(members, d)
		}
	}
	g := Evaluate(r, ds, 0, nil)
	if g.Action != "wait" || g.Members != len(members) {
		t.Fatalf("gate %+v", g)
	}
	for i, d := range members {
		r.Results[d.ID] = i%10 != 0 // 10 % failures, under the 20 % limit
	}
	if g = Evaluate(r, ds, 0, nil); g.Action != "advance" {
		t.Fatalf("expected advance, got %+v", g)
	}
	r.BakeMs, r.WaveStarted = 60000, 0
	if g = Evaluate(r, ds, 1000, nil); g.Action != "wait" || g.Reason != "baking" {
		t.Fatalf("expected bake wait, got %+v", g)
	}
	for i, d := range members {
		r.Results[d.ID] = i%2 == 0 // 50 % failures
	}
	if g = Evaluate(r, ds, 0, nil); g.Action != "halt" {
		t.Fatalf("expected halt, got %+v", g)
	}
}

func TestValidate(t *testing.T) {
	bad := []store.Rollout{
		{Waves: nil, MinReportFraction: 1},
		{Waves: []store.Wave{{Percent: 50}, {Percent: 20}, {Percent: 100}}, MinReportFraction: 1},
		{Waves: []store.Wave{{Percent: 50}}, MinReportFraction: 1},
		{Waves: []store.Wave{{Percent: 100}}, MaxFailureRate: 2, MinReportFraction: 1},
		{Waves: []store.Wave{{Percent: 100}}, MinReportFraction: 0},
	}
	for i, r := range bad {
		if Validate(&r) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
