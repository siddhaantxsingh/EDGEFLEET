// Package store is the control plane's durable state: an append-only
// journal of events plus periodic snapshots.
//
// Journal lines are "<crc32c hex> <json>\n" and fsynced before the API call
// that caused them returns. On open: load snapshot.json (if any), then replay
// journal events with seq > snapshot seq. A torn or corrupt *last* line is
// truncated (crash during append); a bad line followed by more lines is an
// error. Compact() writes a new snapshot atomically and truncates the
// journal.
//
// Only facts that must survive a restart are journaled: enrollments, used
// bootstrap tokens, releases, rollouts and their transitions, update results
// and confirmed versions. Liveness (last heartbeat, metrics) is soft state.
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrCorrupt is returned for a bad journal line that is not the last one.
var ErrCorrupt = errors.New("store: corrupt journal")

// Device is a registered device.
type Device struct {
	ID        string            `json:"id"`
	PublicKey string            `json:"public_key"`
	Labels    map[string]string `json:"labels,omitempty"`
	Version   string            `json:"version"` // last confirmed active version
	Enrolled  int64             `json:"enrolled"`
}

// Release is a signed artifact.
type Release struct {
	Version   string `json:"version"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id,omitempty"` // release key id (key-rotation mode)
	SimHealth string `json:"sim_health,omitempty"`
	Path      string `json:"path"` // artifact file on the server
	Created   int64  `json:"created"`
}

// Wave is one rollout stage: cumulative percentage of targeted devices.
type Wave struct {
	Percent float64 `json:"percent"`
}

// Rollout states.
const (
	Running   = "running"
	Paused    = "paused"
	Halted    = "halted"    // failure gate tripped: devices are rolled back
	Completed = "completed" // every wave passed
	Aborted   = "aborted"   // operator abort: devices are rolled back
)

// Rollout updates a set of devices to a version in waves.
type Rollout struct {
	ID             string            `json:"id"`
	Version        string            `json:"version"`
	FromVersion    string            `json:"from_version"`
	Selector       map[string]string `json:"selector,omitempty"`
	Waves          []Wave            `json:"waves"`
	MaxFailureRate float64           `json:"max_failure_rate"`
	BakeMs         int64             `json:"bake_ms"`
	// stragglers: a wave may advance when this fraction of its devices has reported
	MinReportFraction float64 `json:"min_report_fraction"`
	State             string  `json:"state"`
	Wave              int     `json:"wave"`
	WaveStarted       int64   `json:"wave_started"`
	Reason            string  `json:"reason,omitempty"`
	Created           int64   `json:"created"`
	// per-device outcome for this rollout's version: true success, false failure
	Results map[string]bool `json:"results,omitempty"`
}

// State is everything durable.
type State struct {
	Seq        uint64              `json:"seq"`
	Devices    map[string]*Device  `json:"devices"`
	UsedTokens map[string]bool     `json:"used_tokens"`
	Tokens     map[string]bool     `json:"tokens"` // issued, unused bootstrap tokens
	Releases   map[string]*Release `json:"releases"`
	Rollouts   map[string]*Rollout `json:"rollouts"`
	Order      []string            `json:"rollout_order"`
}

// Event is one journal entry; exactly one payload field is set.
type Event struct {
	Seq     uint64      `json:"seq"`
	Time    int64       `json:"t"`
	Token   string      `json:"token,omitempty"`  // token issued
	Enroll  *Device     `json:"enroll,omitempty"` // device enrolled (consumes Token)
	Release *Release    `json:"release,omitempty"`
	Rollout *Rollout    `json:"rollout,omitempty"` // created or replaced (transition)
	Result  *ResultEvt  `json:"result,omitempty"`
	Version *VersionEvt `json:"version,omitempty"`
}

type ResultEvt struct {
	Rollout string `json:"rollout"`
	Device  string `json:"device"`
	Success bool   `json:"success"`
}

type VersionEvt struct {
	Device  string `json:"device"`
	Version string `json:"version"`
}

// Store wraps State with persistence. Callers hold Mu while reading or
// applying; Append applies and persists one event.
type Store struct {
	Mu  sync.Mutex
	S   *State
	dir string
	j   *os.File
	// Truncated counts bytes cut from a torn journal tail at open.
	Truncated int64
	NoSync    bool // tests/benchmarks only
}

func newState() *State {
	return &State{Devices: map[string]*Device{}, UsedTokens: map[string]bool{}, Tokens: map[string]bool{},
		Releases: map[string]*Release{}, Rollouts: map[string]*Rollout{}}
}

// Open loads the snapshot and replays the journal.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	st := &Store{S: newState(), dir: dir}
	if b, err := os.ReadFile(filepath.Join(dir, "snapshot.json")); err == nil {
		if err := json.Unmarshal(b, st.S); err != nil {
			return nil, fmt.Errorf("store: snapshot: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	jp := filepath.Join(dir, "journal.log")
	b, err := os.ReadFile(jp)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	good := 0
	for good < len(b) {
		nl := bytes.IndexByte(b[good:], '\n')
		if nl < 0 {
			break // torn final line
		}
		line := b[good : good+nl]
		ev, ok := parseLine(line)
		if !ok {
			if good+nl+1 < len(b) {
				return nil, fmt.Errorf("%w at byte %d", ErrCorrupt, good)
			}
			break
		}
		if ev.Seq > st.S.Seq {
			apply(st.S, ev)
		}
		good += nl + 1
	}
	if good < len(b) {
		st.Truncated = int64(len(b) - good)
		if err := os.Truncate(jp, int64(good)); err != nil {
			return nil, err
		}
	}
	st.j, err = os.OpenFile(jp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return st, nil
}

func parseLine(line []byte) (*Event, bool) {
	sp := bytes.IndexByte(line, ' ')
	if sp != 8 {
		return nil, false
	}
	var crc uint32
	if _, err := fmt.Sscanf(string(line[:8]), "%08x", &crc); err != nil {
		return nil, false
	}
	body := line[9:]
	if crc32.Checksum(body, crcTable) != crc {
		return nil, false
	}
	var ev Event
	if json.Unmarshal(body, &ev) != nil {
		return nil, false
	}
	return &ev, true
}

func apply(s *State, ev *Event) {
	s.Seq = ev.Seq
	switch {
	case ev.Enroll != nil:
		d := *ev.Enroll
		s.Devices[d.ID] = &d
		if ev.Token != "" {
			delete(s.Tokens, ev.Token)
			s.UsedTokens[ev.Token] = true
		}
	case ev.Token != "":
		s.Tokens[ev.Token] = true
	case ev.Release != nil:
		r := *ev.Release
		s.Releases[r.Version] = &r
	case ev.Rollout != nil:
		r := *ev.Rollout
		if _, ok := s.Rollouts[r.ID]; !ok {
			s.Order = append(s.Order, r.ID)
		}
		if r.Results == nil {
			if old, ok := s.Rollouts[r.ID]; ok {
				r.Results = old.Results
			} else {
				r.Results = map[string]bool{}
			}
		}
		s.Rollouts[r.ID] = &r
	case ev.Result != nil:
		if r, ok := s.Rollouts[ev.Result.Rollout]; ok {
			if r.Results == nil {
				r.Results = map[string]bool{}
			}
			r.Results[ev.Result.Device] = ev.Result.Success
		}
	case ev.Version != nil:
		if d, ok := s.Devices[ev.Version.Device]; ok {
			d.Version = ev.Version.Version
		}
	}
}

// Append applies ev to the state and makes it durable. Caller holds Mu.
func (st *Store) Append(ev Event, now int64) error {
	ev.Seq = st.S.Seq + 1
	ev.Time = now
	if ev.Rollout != nil {
		cp := *ev.Rollout
		cp.Results = nil // results are journaled individually
		ev.Rollout = &cp
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("%08x %s\n", crc32.Checksum(body, crcTable), body)
	if _, err := st.j.WriteString(line); err != nil {
		return err
	}
	if !st.NoSync {
		if err := st.j.Sync(); err != nil {
			return err
		}
	}
	apply(st.S, &ev)
	return nil
}

// Compact writes a snapshot and truncates the journal. Caller holds Mu.
func (st *Store) Compact() error {
	b, err := json.Marshal(st.S)
	if err != nil {
		return err
	}
	tmp := filepath.Join(st.dir, "snapshot.json.tmp")
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	w.Write(b)
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Rename(tmp, filepath.Join(st.dir, "snapshot.json")); err != nil {
		return err
	}
	if d, err := os.Open(st.dir); err == nil {
		d.Sync()
		d.Close()
	}
	// a crash after the rename but before the truncate replays nothing new
	// (journal events have seq <= snapshot seq)
	if err := st.j.Truncate(0); err != nil {
		return err
	}
	_, err = st.j.Seek(0, 0)
	return err
}

// Close closes the journal.
func (st *Store) Close() error { return st.j.Close() }
