package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type kp struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKP() kp {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return kp{pub, priv}
}

func (k kp) entry(id string) ReleaseKey {
	return ReleaseKey{ID: id, PublicKey: base64.StdEncoding.EncodeToString(k.pub)}
}

var t0 = time.Unix(1_800_000_000, 0)

func TestKeySetRotationLifecycle(t *testing.T) {
	root, k1, k2 := newKP(), newKP(), newKP()
	m := &Manifest{Version: "2.0", Size: 3, SHA256: "aa"}
	tr := &Trust{Root: root.pub}

	// no key set yet: nothing verifies
	if err := tr.VerifyRelease(m, SignManifest(k1.priv, m), "k1", t0); !errors.Is(err, ErrNoTrustedKeySet) {
		t.Fatalf("want ErrNoTrustedKeySet, got %v", err)
	}

	v1 := SignKeySet(root.priv, KeySet{Version: 1, Expires: t0.Add(24 * time.Hour).Unix(), Keys: []ReleaseKey{k1.entry("k1")}})
	if ch, err := tr.Accept(&v1, t0); err != nil || !ch {
		t.Fatalf("v1: %v %v", ch, err)
	}
	if err := tr.VerifyRelease(m, SignManifest(k1.priv, m), "k1", t0); err != nil {
		t.Fatalf("k1 release under v1: %v", err)
	}
	// k2 is not authorised yet
	if err := tr.VerifyRelease(m, SignManifest(k2.priv, m), "k2", t0); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("k2 under v1: %v", err)
	}
	// a signature by k2 that claims to be k1 fails
	if err := tr.VerifyRelease(m, SignManifest(k2.priv, m), "k1", t0); err == nil {
		t.Fatal("k2 signature accepted under id k1")
	}

	// re-delivering the same set is a no-op
	if ch, err := tr.Accept(&v1, t0); err != nil || ch {
		t.Fatalf("same v1 again: %v %v", ch, err)
	}

	// rotate: v2 adds k2 and revokes k1
	v2 := SignKeySet(root.priv, KeySet{Version: 2, Expires: t0.Add(48 * time.Hour).Unix(),
		Keys: []ReleaseKey{k2.entry("k2")}, Revoked: []string{"k1"}})
	if ch, err := tr.Accept(&v2, t0.Add(time.Hour)); err != nil || !ch {
		t.Fatalf("v2: %v %v", ch, err)
	}
	if err := tr.VerifyRelease(m, SignManifest(k2.priv, m), "k2", t0.Add(time.Hour)); err != nil {
		t.Fatalf("k2 under v2: %v", err)
	}
	if err := tr.VerifyRelease(m, SignManifest(k1.priv, m), "k1", t0.Add(time.Hour)); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("revoked k1: %v", err)
	}

	// rollback: the old v1 (still validly signed, not expired) is refused,
	// so a revoked key cannot be brought back
	if _, err := tr.Accept(&v1, t0.Add(time.Hour)); !errors.Is(err, ErrKeySetRollback) {
		t.Fatalf("rollback to v1: %v", err)
	}
	if tr.Current.KeySet.Version != 2 {
		t.Fatal("current set changed after a refused rollback")
	}

	// un-revoking k1 in a newer set is refused
	v3unrevoke := SignKeySet(root.priv, KeySet{Version: 3, Expires: t0.Add(48 * time.Hour).Unix(), Keys: []ReleaseKey{k1.entry("k1"), k2.entry("k2")}})
	if _, err := tr.Accept(&v3unrevoke, t0.Add(time.Hour)); !errors.Is(err, ErrUnrevoked) {
		t.Fatalf("un-revoking k1: %v", err)
	}

	// equivocation: a different v2
	v2b := SignKeySet(root.priv, KeySet{Version: 2, Expires: t0.Add(48 * time.Hour).Unix(), Keys: []ReleaseKey{k1.entry("k1")}})
	if _, err := tr.Accept(&v2b, t0.Add(time.Hour)); !errors.Is(err, ErrKeySetConflict) {
		t.Fatalf("conflicting v2: %v", err)
	}

	// expiry: after v2 expires no release verifies (freeze protection),
	// and an expired set is refused even if newer
	late := t0.Add(49 * time.Hour)
	if err := tr.VerifyRelease(m, SignManifest(k2.priv, m), "k2", late); !errors.Is(err, ErrKeySetExpired) {
		t.Fatalf("release under expired set: %v", err)
	}
	v3old := SignKeySet(root.priv, KeySet{Version: 3, Expires: late.Add(-time.Minute).Unix(), Keys: []ReleaseKey{k2.entry("k2")}, Revoked: []string{"k1"}})
	if _, err := tr.Accept(&v3old, late); !errors.Is(err, ErrKeySetExpired) {
		t.Fatalf("expired v3: %v", err)
	}
	// a fresh v3 restores updates
	v3 := SignKeySet(root.priv, KeySet{Version: 3, Expires: late.Add(24 * time.Hour).Unix(), Keys: []ReleaseKey{k2.entry("k2")}, Revoked: []string{"k1"}})
	if _, err := tr.Accept(&v3, late); err != nil {
		t.Fatal(err)
	}
	if err := tr.VerifyRelease(m, SignManifest(k2.priv, m), "k2", late); err != nil {
		t.Fatal(err)
	}
}

func TestKeySetSignatureAndStructure(t *testing.T) {
	root, other, k1 := newKP(), newKP(), newKP()
	exp := t0.Add(time.Hour).Unix()
	good := SignKeySet(root.priv, KeySet{Version: 1, Expires: exp, Keys: []ReleaseKey{k1.entry("k1")}})
	if err := VerifyKeySet(root.pub, &good, t0); err != nil {
		t.Fatal(err)
	}
	// signed by a key other than the pinned root
	forged := SignKeySet(other.priv, good.KeySet)
	if err := VerifyKeySet(root.pub, &forged, t0); !errors.Is(err, ErrKeySetSignature) {
		t.Fatalf("forged: %v", err)
	}
	// any field changed after signing
	for name, mut := range map[string]func(*KeySet){
		"version": func(k *KeySet) { k.Version = 9 },
		"expires": func(k *KeySet) { k.Expires += 3600 },
		"key":     func(k *KeySet) { k.Keys = append(k.Keys, other.entry("evil")) },
		"revoked": func(k *KeySet) { k.Revoked = []string{"x"} },
		"id":      func(k *KeySet) { k.Keys[0].ID = "k9" },
	} {
		c := good
		c.KeySet.Keys = append([]ReleaseKey(nil), good.KeySet.Keys...)
		mut(&c.KeySet)
		if err := VerifyKeySet(root.pub, &c, t0); !errors.Is(err, ErrKeySetSignature) {
			t.Fatalf("%s modified: %v", name, err)
		}
	}
	// malformed sets are refused even when correctly signed
	for name, ks := range map[string]KeySet{
		"version 0":         {Version: 0, Expires: exp, Keys: []ReleaseKey{k1.entry("k1")}},
		"no keys":           {Version: 1, Expires: exp},
		"duplicate id":      {Version: 1, Expires: exp, Keys: []ReleaseKey{k1.entry("k1"), other.entry("k1")}},
		"bad public key":    {Version: 1, Expires: exp, Keys: []ReleaseKey{{ID: "k1", PublicKey: "AAAA"}}},
		"valid and revoked": {Version: 1, Expires: exp, Keys: []ReleaseKey{k1.entry("k1")}, Revoked: []string{"k1"}},
		"colon in id":       {Version: 1, Expires: exp, Keys: []ReleaseKey{k1.entry("a:b")}},
	} {
		s := SignKeySet(root.priv, ks)
		if err := VerifyKeySet(root.pub, &s, t0); !errors.Is(err, ErrKeySetInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// the canonical bytes do not depend on key order, and JSON round-trips
	a := KeySet{Version: 1, Expires: exp, Keys: []ReleaseKey{k1.entry("a"), other.entry("b")}}
	b := KeySet{Version: 1, Expires: exp, Keys: []ReleaseKey{other.entry("b"), k1.entry("a")}}
	if string(a.Bytes()) != string(b.Bytes()) {
		t.Fatal("canonical encoding depends on key order")
	}
	var rt SignedKeySet
	if err := json.Unmarshal(MustJSON(good), &rt); err != nil || VerifyKeySet(root.pub, &rt, t0) != nil {
		t.Fatalf("JSON round trip: %v", err)
	}
}
