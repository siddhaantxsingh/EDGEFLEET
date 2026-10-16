package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestManifestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := &Manifest{Version: "1.2.3", Size: 10, SHA256: "ab"}
	sig := SignManifest(priv, m)
	if VerifyManifest(pub, m, sig) != nil {
		t.Fatal("valid signature rejected")
	}
	for _, mut := range []func(*Manifest){
		func(m *Manifest) { m.Version = "1.2.4" }, func(m *Manifest) { m.Size = 11 },
		func(m *Manifest) { m.SHA256 = "ac" }, func(m *Manifest) { m.SimHealth = "fail" },
	} {
		c := *m
		mut(&c)
		if VerifyManifest(pub, &c, sig) == nil {
			t.Fatalf("modified manifest %+v accepted", c)
		}
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyManifest(other, m, sig) == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestRequestAuthTamperSkewReplay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	body := []byte(`{"device_id":"d1"}`)
	mk := func() *http.Request {
		r, _ := http.NewRequest("POST", "http://x/v1/heartbeat", bytes.NewReader(body))
		SignRequest(r, "d1", priv, body, now)
		return r
	}
	lookup := func(id string) (ed25519.PublicKey, bool) { return pub, id == "d1" }
	seen := map[string]bool{}
	nonce := func(id, n string, ts int64) bool { k := id + n; d := seen[k]; seen[k] = true; return d }

	r := mk()
	if id, err := VerifyRequest(r, body, now, lookup, nonce); err != nil || id != "d1" {
		t.Fatalf("valid request rejected: %v", err)
	}
	if _, err := VerifyRequest(r, body, now, lookup, nonce); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay accepted: %v", err)
	}
	if _, err := VerifyRequest(mk(), []byte(`{"device_id":"d2"}`), now, lookup, nonce); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered body accepted: %v", err)
	}
	r = mk()
	r.URL.Path = "/v1/admin/tokens"
	if _, err := VerifyRequest(r, body, now, lookup, nonce); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("path change accepted: %v", err)
	}
	if _, err := VerifyRequest(mk(), body, now.Add(10*time.Minute), lookup, nonce); !errors.Is(err, ErrStale) {
		t.Fatalf("stale request accepted: %v", err)
	}
	r = mk()
	r.Header.Set("X-Device-ID", "d9")
	if _, err := VerifyRequest(r, body, now, lookup, nonce); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("unknown device accepted: %v", err)
	}
}
