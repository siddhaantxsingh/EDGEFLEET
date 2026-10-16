// Package rollout holds the pure decision logic for staged rollouts:
// which devices belong to which wave, what version each device should run,
// and when a wave may advance or must halt.
//
// Wave membership is deterministic: rank(device) = first 8 bytes of
// SHA-256(rolloutID || deviceID) / 2^64, uniform on [0,1). A device is in
// wave w if rank < Waves[w].Percent/100 (cumulative), so membership never
// changes while a rollout runs, survives server restarts without being
// stored, and differs between rollouts (the same devices are not always the
// canaries).
package rollout

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"edgefleet/internal/store"
)

// Rank is the device's position in [0,1) for this rollout.
func Rank(rolloutID, deviceID string) float64 {
	h := sha256.Sum256([]byte(rolloutID + "\x00" + deviceID))
	return float64(binary.BigEndian.Uint64(h[:8])>>11) / float64(uint64(1)<<53)
}

// WaveOf returns the first wave containing the device, or -1.
func WaveOf(r *store.Rollout, deviceID string) int {
	x := Rank(r.ID, deviceID)
	for i, w := range r.Waves {
		if x < w.Percent/100 {
			return i
		}
	}
	return -1
}

// Selected reports whether the device matches the rollout's label selector.
func Selected(r *store.Rollout, d *store.Device) bool {
	for k, v := range r.Selector {
		if d.Labels[k] != v {
			return false
		}
	}
	return true
}

// Validate checks a new rollout's parameters.
func Validate(r *store.Rollout) error {
	if len(r.Waves) == 0 {
		return fmt.Errorf("rollout needs at least one wave")
	}
	prev := 0.0
	for i, w := range r.Waves {
		if w.Percent <= prev || w.Percent > 100 {
			return fmt.Errorf("wave %d: percentages must increase and be <= 100", i)
		}
		prev = w.Percent
	}
	if r.Waves[len(r.Waves)-1].Percent != 100 {
		return fmt.Errorf("the last wave must reach 100%%")
	}
	if r.MaxFailureRate < 0 || r.MaxFailureRate > 1 {
		return fmt.Errorf("max_failure_rate must be in [0,1]")
	}
	if r.MinReportFraction <= 0 || r.MinReportFraction > 1 {
		return fmt.Errorf("min_report_fraction must be in (0,1]")
	}
	return nil
}

// Desired returns the version a device should run given the rollout
// ("" means: no instruction, keep the current version).
func Desired(r *store.Rollout, d *store.Device) string {
	if r == nil || !Selected(r, d) {
		return ""
	}
	w := WaveOf(r, d.ID)
	if w < 0 {
		return ""
	}
	switch r.State {
	case store.Running, store.Paused, store.Completed:
		if r.State == store.Paused && d.Version != r.Version {
			return "" // paused: start no new updates
		}
		if w > r.Wave && r.State != store.Completed {
			return ""
		}
		if ok, reported := r.Results[d.ID]; reported && !ok {
			return "" // this device failed the update and rolled back: do not retry
		}
		return r.Version
	case store.Halted, store.Aborted:
		// roll back devices that took the new version
		if d.Version == r.Version && r.FromVersion != "" {
			return r.FromVersion
		}
	}
	return ""
}

// Gate is the decision for the current wave.
type Gate struct {
	Action   string // "wait", "advance", "complete", "halt"
	Members  int    // selected devices in waves <= current
	Reported int
	Failed   int
	Reason   string
}

// Evaluate decides whether the current wave may advance. `online` reports
// whether a device has been heard from recently; offline devices that have
// not reported are not waited for once MinReportFraction is met.
func Evaluate(r *store.Rollout, devices []*store.Device, now int64, online func(id string) bool) Gate {
	g := Gate{Action: "wait"}
	for _, d := range devices {
		if !Selected(r, d) {
			continue
		}
		w := WaveOf(r, d.ID)
		if w < 0 || w > r.Wave {
			continue
		}
		g.Members++
		if ok, rep := r.Results[d.ID]; rep {
			g.Reported++
			if !ok {
				g.Failed++
			}
		} else if d.Version == r.Version {
			g.Reported++ // already on the target version before this rollout
		}
	}
	if g.Reported > 0 && float64(g.Failed)/float64(g.Reported) > r.MaxFailureRate {
		g.Action = "halt"
		g.Reason = fmt.Sprintf("wave %d: %d of %d reporting devices failed (limit %.0f%%)", r.Wave, g.Failed, g.Reported, 100*r.MaxFailureRate)
		return g
	}
	if g.Members == 0 {
		g.Reason = "no devices in this wave yet"
	} else if float64(g.Reported) < r.MinReportFraction*float64(g.Members) {
		g.Reason = fmt.Sprintf("%d of %d devices reported", g.Reported, g.Members)
		return g
	}
	if now-r.WaveStarted < r.BakeMs {
		g.Reason = "baking"
		return g
	}
	if r.Wave == len(r.Waves)-1 {
		g.Action = "complete"
	} else {
		g.Action = "advance"
	}
	_ = online
	return g
}
