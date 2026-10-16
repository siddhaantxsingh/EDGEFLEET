package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func fill(t *testing.T, s *Store) {
	for i := 0; i < 20; i++ {
		s.Append(Event{Token: fmt.Sprintf("tok%d", i)}, int64(i))
		s.Append(Event{Token: fmt.Sprintf("tok%d", i), Enroll: &Device{ID: fmt.Sprintf("d%d", i), Version: "1"}}, int64(i))
	}
	s.Append(Event{Release: &Release{Version: "2"}}, 99)
	s.Append(Event{Rollout: &Rollout{ID: "r", Version: "2", State: Running, Waves: []Wave{{Percent: 100}}}}, 100)
	s.Append(Event{Result: &ResultEvt{Rollout: "r", Device: "d3", Success: false}}, 101)
	s.Append(Event{Version: &VersionEvt{Device: "d4", Version: "2"}}, 102)
	s.Append(Event{Rollout: &Rollout{ID: "r", Version: "2", State: Halted, Waves: []Wave{{Percent: 100}}}}, 103)
}

func TestReplayAndCompaction(t *testing.T) {
	d := t.TempDir()
	s, _ := Open(d)
	fill(t, s)
	want := s.S.Seq
	s.Close()
	s2, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	check := func(s *Store) {
		if s.S.Seq != want || len(s.S.Devices) != 20 || len(s.S.Tokens) != 0 || !s.S.UsedTokens["tok5"] ||
			s.S.Devices["d4"].Version != "2" || s.S.Rollouts["r"].State != Halted || s.S.Rollouts["r"].Results["d3"] {
			t.Fatalf("bad state after replay: seq=%d want=%d dev=%d tok=%d used=%v d4=%q state=%q", s.S.Seq, want, len(s.S.Devices), len(s.S.Tokens), s.S.UsedTokens["tok5"], s.S.Devices["d4"].Version, s.S.Rollouts["r"].State)
		}
		if ok, rep := s.S.Rollouts["r"].Results["d3"]; ok || !rep {
			t.Fatal("rollout transition lost the journaled results")
		}
	}
	check(s2)
	s2.Compact()
	s2.Append(Event{Token: "after"}, 200)
	s2.Close()
	s3, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if !s3.S.Tokens["after"] {
		t.Fatal("event after compaction lost")
	}
	delete(s3.S.Tokens, "after") // issued on purpose above
	want++
	check(s3)
}

func TestJournalCrashAtEveryByte(t *testing.T) {
	src := t.TempDir()
	s, _ := Open(src)
	fill(t, s)
	s.Close()
	full, _ := os.ReadFile(filepath.Join(src, "journal.log"))
	var ends []int
	for i, c := range full {
		if c == '\n' {
			ends = append(ends, i+1)
		}
	}
	for cut := 0; cut <= len(full); cut++ {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "journal.log"), full[:cut], 0o644)
		r, err := Open(d)
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		want := 0
		for _, e := range ends {
			if cut >= e {
				want++
			}
		}
		if int(r.S.Seq) != want {
			t.Fatalf("cut %d: replayed %d events, want %d", cut, r.S.Seq, want)
		}
		r.Close()
	}
}

func TestMidJournalCorruptionIsAnError(t *testing.T) {
	d := t.TempDir()
	s, _ := Open(d)
	fill(t, s)
	s.Close()
	p := filepath.Join(d, "journal.log")
	b, _ := os.ReadFile(p)
	b[30] ^= 0x20
	os.WriteFile(p, b, 0o644)
	if _, err := Open(d); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}
