package proto

// Release-signing key rotation.
//
// Devices pin one long-lived ROOT public key (kept offline by the operator).
// The root signs a KEY SET: a version number, an expiry time, the release
// keys that are currently valid, and the ids of revoked keys. Releases are
// signed by one of the release keys and name it with a key id.
//
// A device accepts a key set only if
//   - the root signature verifies,
//   - it has not expired,
//   - its version is not lower than the version the device already trusts
//     (no rollback to an older set that still lists a since-revoked key), and
//   - at an equal version it is byte-identical to the trusted one, and
//   - it keeps every revocation of the trusted set (revocation is permanent).
//
// It accepts a release only if the key that signed it is in its trusted,
// unexpired key set and not revoked. An expired trusted set blocks all
// updates until a fresh one arrives (freeze protection).
//
// This is a small subset of what TUF provides. There are no separate
// targets/snapshot/timestamp roles, no signature thresholds, and the root
// key itself cannot be rotated.

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReleaseKey is one release-signing public key in a key set.
type ReleaseKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"` // base64 Ed25519
}

// KeySet lists the release keys the root currently authorises.
type KeySet struct {
	Version uint64       `json:"version"`
	Expires int64        `json:"expires"` // unix seconds
	Keys    []ReleaseKey `json:"keys"`
	Revoked []string     `json:"revoked,omitempty"`
}

// SignedKeySet is a key set with the root's signature over KeySet.Bytes().
type SignedKeySet struct {
	KeySet    KeySet `json:"key_set"`
	Signature string `json:"signature"`
}

// Key-set errors.
var (
	ErrKeySetSignature = errors.New("key set: root signature invalid")
	ErrKeySetExpired   = errors.New("key set: expired")
	ErrKeySetRollback  = errors.New("key set: version older than the trusted one")
	ErrKeySetConflict  = errors.New("key set: same version as the trusted one but different content")
	ErrKeySetInvalid   = errors.New("key set: malformed")
	ErrNoTrustedKeySet = errors.New("no trusted key set")
	ErrUnknownKey      = errors.New("release key not in the trusted key set")
	ErrRevokedKey      = errors.New("release key revoked")
	ErrUnrevoked       = errors.New("key set: drops a revocation of the trusted set")
)

// Bytes is the canonical encoding that the root key signs. Keys and revoked
// ids are sorted, so the encoding does not depend on JSON field order.
func (k *KeySet) Bytes() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "edgefleet-keyset-v1\nversion=%d\nexpires=%d\n", k.Version, k.Expires)
	keys := append([]ReleaseKey(nil), k.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	for _, x := range keys {
		fmt.Fprintf(&b, "key=%s:%s\n", x.ID, x.PublicKey)
	}
	rev := append([]string(nil), k.Revoked...)
	sort.Strings(rev)
	for _, r := range rev {
		fmt.Fprintf(&b, "revoked=%s\n", r)
	}
	return []byte(b.String())
}

func (k *KeySet) validate() error {
	if k.Version == 0 || len(k.Keys) == 0 {
		return ErrKeySetInvalid
	}
	seen := map[string]bool{}
	for _, x := range k.Keys {
		if x.ID == "" || strings.ContainsAny(x.ID, ":\n") || seen[x.ID] {
			return ErrKeySetInvalid
		}
		seen[x.ID] = true
		if _, err := DecodePublicKey(x.PublicKey); err != nil {
			return ErrKeySetInvalid
		}
	}
	for _, r := range k.Revoked {
		if r == "" || strings.Contains(r, "\n") || seen[r] {
			return ErrKeySetInvalid // a key cannot be both valid and revoked
		}
	}
	return nil
}

// SignKeySet signs a key set with the root private key.
func SignKeySet(root ed25519.PrivateKey, k KeySet) SignedKeySet {
	return SignedKeySet{KeySet: k, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(root, k.Bytes()))}
}

// VerifyKeySet checks the root signature, the structure and the expiry.
func VerifyKeySet(root ed25519.PublicKey, s *SignedKeySet, now time.Time) error {
	if s == nil {
		return ErrNoTrustedKeySet
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(root, s.KeySet.Bytes(), sig) {
		return ErrKeySetSignature
	}
	if err := s.KeySet.validate(); err != nil {
		return err
	}
	if now.Unix() >= s.KeySet.Expires {
		return ErrKeySetExpired
	}
	return nil
}

// Trust is a device's (or the server's) view of the key hierarchy: the
// pinned root key and the newest key set accepted so far.
type Trust struct {
	Root    ed25519.PublicKey
	Current *SignedKeySet
}

// Accept validates s against the root and the current set and, if it is
// acceptable, makes it current. It reports whether the current set changed.
// On error the current set is left unchanged.
func (t *Trust) Accept(s *SignedKeySet, now time.Time) (bool, error) {
	if err := VerifyKeySet(t.Root, s, now); err != nil {
		return false, err
	}
	if c := t.Current; c != nil {
		switch {
		case s.KeySet.Version < c.KeySet.Version:
			return false, ErrKeySetRollback
		case s.KeySet.Version == c.KeySet.Version:
			if string(s.KeySet.Bytes()) != string(c.KeySet.Bytes()) {
				return false, ErrKeySetConflict
			}
			return false, nil
		}
		// revocations are permanent: a newer set must keep every id the
		// trusted set revoked (and so cannot authorise it again)
		keep := map[string]bool{}
		for _, r := range s.KeySet.Revoked {
			keep[r] = true
		}
		for _, r := range c.KeySet.Revoked {
			if !keep[r] {
				return false, fmt.Errorf("%w: %s", ErrUnrevoked, r)
			}
		}
	}
	cp := *s
	cp.KeySet.Keys = append([]ReleaseKey(nil), s.KeySet.Keys...)
	cp.KeySet.Revoked = append([]string(nil), s.KeySet.Revoked...)
	t.Current = &cp
	return true, nil
}

// VerifyRelease checks a manifest signature made by release key keyID
// against the current, unexpired key set.
func (t *Trust) VerifyRelease(m *Manifest, sig, keyID string, now time.Time) error {
	c := t.Current
	if c == nil {
		return ErrNoTrustedKeySet
	}
	if now.Unix() >= c.KeySet.Expires {
		return ErrKeySetExpired
	}
	for _, r := range c.KeySet.Revoked {
		if r == keyID {
			return fmt.Errorf("%w: %s", ErrRevokedKey, keyID)
		}
	}
	for _, k := range c.KeySet.Keys {
		if k.ID == keyID {
			pub, err := DecodePublicKey(k.PublicKey)
			if err != nil {
				return ErrKeySetInvalid
			}
			return VerifyManifest(pub, m, sig)
		}
	}
	return fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
}
