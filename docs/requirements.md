# Requirements matrix — Project 20 (EdgeFleet)

| Requirement | Status | Evidence |
|---|---|---|
| Device enrollment with identity | VERIFIED | single-use tokens; Ed25519 device keys; tests |
| Authenticated device API (replay-safe) | VERIFIED | proto tests; unsigned/replayed requests refused |
| Signed releases, verified on device | VERIFIED | server rejects unsigned; agent rejects tampered (tests) |
| A/B updates with automatic rollback | VERIFIED | crash at every step; boot counter; real-process e2e |
| Staged rollouts (waves, gates, bake) | VERIFIED | rollout tests; fleetsim 2,000 devices |
| Automatic halt of bad releases | VERIFIED | blast radius 15 / 2,000 devices |
| Pause / resume / abort | VERIFIED | abort rolls back (test) |
| Resumable downloads | VERIFIED | Range test (only missing bytes sent) |
| Durable control-plane state, crash-safe | VERIFIED | journal cut at every byte; restart mid-rollout |
| Fleet-scale simulation and measurement | VERIFIED | `cmd/fleetsim`, docs/benchmarks.md |
| Observability | VERIFIED (basic) | `/metrics` (devices by version, rollout wave, heartbeats, auth failures) |
| Admin CLI | VERIFIED | `fleetctl` used by e2e |
| HA / multi-instance control plane | NOT IMPLEMENTED | — |
| Release-signing key rotation: root-signed key set with version and expiry; devices pin the root; expired, revoked, unknown keys and key-set rollback rejected | VERIFIED (2026-10-15) | `internal/proto/keyset_test.go` (rotation lifecycle, forgery, malformed sets); `internal/server/keyset_test.go` (server + agents, incl. a tampering control plane serving revoked-key signatures and a rolled-back key set; device-clock expiry; restart keeps the version floor); `e2e/TestKeyRotationWithRealBinaries` (fleetctl keyset/keyset-push, fleetd, fleet-agent). 7 of 7 hand mutations caught: [keyset_mutations.log](evidence/2026-10-15/keyset_mutations.log). Full run: [go_test_all.log](evidence/2026-10-15/go_test_all.log) |
| TUF (roles, thresholds, root rotation, snapshot/timestamp metadata) | NOT IMPLEMENTED | the key set is a small subset; see docs/limitations.md |
| Device-key rotation / revocation | NOT IMPLEMENTED | — |
| Delta updates | NOT IMPLEMENTED | — |
| CI | VERIFIED | `.github/workflows/edgefleet.yml` (run 38517425606 green) |
