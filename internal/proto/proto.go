// Package proto defines the device <-> control-plane messages and their
// authentication.
//
// Device requests are authenticated with Ed25519: the device generates its
// key pair at enrollment and registers the public key; every later request
// carries headers
//
//	X-Device-ID, X-Timestamp (unix ms), X-Nonce (random hex), X-Signature
//
// where the signature covers "METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body)".
// The server rejects timestamps more than MaxSkew away and nonces it has
// seen within that window (replay protection).
//
// Releases are signed by an offline release key: the signature covers the
// canonical manifest bytes (version, size, SHA-256 of the artifact). Agents
// pin the release public key and verify both the signature and the digest of
// the downloaded artifact before installing.
package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// MaxSkew bounds clock skew and the nonce-replay window.
const MaxSkew = 5 * time.Minute

// EnrollRequest registers a device using a one-time bootstrap token.
type EnrollRequest struct {
	Token     string            `json:"token"`
	DeviceID  string            `json:"device_id"`
	PublicKey string            `json:"public_key"` // base64 Ed25519
	Labels    map[string]string `json:"labels,omitempty"`
	Version   string            `json:"version"` // version installed at manufacturing
}

// Heartbeat is sent periodically by every agent.
type Heartbeat struct {
	DeviceID      string `json:"device_id"`
	ActiveVersion string `json:"active_version"`
	State         string `json:"state"` // idle | downloading | installing | trial | failed
	TargetVersion string `json:"target_version,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	// Result reports the outcome of the last update attempt exactly once.
	Result  *UpdateResult      `json:"result,omitempty"`
	Metrics map[string]float64 `json:"metrics,omitempty"`
}

// UpdateResult is reported after a trial boot finishes.
type UpdateResult struct {
	Version    string `json:"version"`
	Success    bool   `json:"success"`
	Reason     string `json:"reason,omitempty"`
	RolledBack bool   `json:"rolled_back"`
}

// Desired is the server's answer to a heartbeat.
type Desired struct {
	Version     string    `json:"version,omitempty"` // "" = keep what you have
	Manifest    *Manifest `json:"manifest,omitempty"`
	Signature   string    `json:"signature,omitempty"` // base64 Ed25519 over Manifest.Bytes()
	ArtifactURL string    `json:"artifact_url,omitempty"`
	// Key-rotation mode: the release key that signed the manifest, and the
	// server's current root-signed key set (see keyset.go).
	KeyID        string        `json:"key_id,omitempty"`
	KeySet       *SignedKeySet `json:"key_set,omitempty"`
	HeartbeatSec int           `json:"heartbeat_sec"`
}

// Manifest describes a release artifact.
type Manifest struct {
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	// Simulated health outcome for fleetsim devices that do not execute
	// artifacts: "ok", "fail", or "flaky:<probability of failure>".
	SimHealth string `json:"sim_health,omitempty"`
}

// Bytes is the canonical encoding that the release key signs.
func (m *Manifest) Bytes() []byte {
	return []byte(fmt.Sprintf("edgefleet-manifest-v1\nversion=%s\nsize=%d\nsha256=%s\nsim_health=%s\n",
		m.Version, m.Size, m.SHA256, m.SimHealth))
}

// SignManifest signs a manifest with the release private key.
func SignManifest(priv ed25519.PrivateKey, m *Manifest) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m.Bytes()))
}

// VerifyManifest checks a manifest signature against the pinned release key.
func VerifyManifest(pub ed25519.PublicKey, m *Manifest, sig string) error {
	s, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || !ed25519.Verify(pub, m.Bytes(), s) {
		return errors.New("manifest signature invalid")
	}
	return nil
}

// ------------------------------------------------------------ request auth

func signingString(method, path string, ts int64, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(fmt.Sprintf("%s\n%s\n%d\n%s\n%s", method, path, ts, nonce, hex.EncodeToString(h[:])))
}

// SignRequest adds device authentication headers to req.
func SignRequest(req *http.Request, deviceID string, priv ed25519.PrivateKey, body []byte, now time.Time) {
	var nb [16]byte
	rand.Read(nb[:])
	nonce := hex.EncodeToString(nb[:])
	ts := now.UnixMilli()
	sig := ed25519.Sign(priv, signingString(req.Method, req.URL.Path, ts, nonce, body))
	req.Header.Set("X-Device-ID", deviceID)
	req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(sig))
}

// Auth errors.
var (
	ErrUnknownDevice = errors.New("unknown device")
	ErrBadSignature  = errors.New("bad signature")
	ErrStale         = errors.New("timestamp outside the allowed skew")
	ErrReplay        = errors.New("nonce reused")
)

// VerifyRequest checks the signature headers. lookup returns the device's
// public key; seen records a nonce and reports whether it was already used.
func VerifyRequest(r *http.Request, body []byte, now time.Time,
	lookup func(id string) (ed25519.PublicKey, bool), seen func(id, nonce string, ts int64) bool) (string, error) {
	id := r.Header.Get("X-Device-ID")
	pub, ok := lookup(id)
	if !ok {
		return "", ErrUnknownDevice
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-Timestamp"), 10, 64)
	if err != nil {
		return "", ErrStale
	}
	if d := now.Sub(time.UnixMilli(ts)); d > MaxSkew || d < -MaxSkew {
		return "", ErrStale
	}
	nonce := r.Header.Get("X-Nonce")
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Signature"))
	if err != nil || len(nonce) != 32 || !ed25519.Verify(pub, signingString(r.Method, r.URL.Path, ts, nonce, body), sig) {
		return "", ErrBadSignature
	}
	if seen(id, nonce, ts) {
		return "", ErrReplay
	}
	return id, nil
}

// DecodePublicKey parses a base64 Ed25519 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// MustJSON marshals or panics (for fixed, known-good types).
func MustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
