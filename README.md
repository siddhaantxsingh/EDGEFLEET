# EdgeFleet: fleet management and safe OTA updates

EdgeFleet is a control plane, a device agent and a CLI for updating fleets of edge devices safely, written in Go with only the standard library. It provides:

- **signed releases**, verified on the device, with optional **release-key rotation** (a pinned root key signs a versioned, expiring key set; revoked keys and key-set rollback are refused; not TUF);
- **Ed25519 device identity** with replay-safe signed requests;
- **A/B installs** with trial boots, health checks and **automatic rollback**;
- **staged rollouts**, whose health gates halt a bad release at the canary and roll it back.

The state on both sides survives a crash at any step.

**Status:**
- **Done:** verified locally, including the real binaries running real executable artifacts, and a 2,000-device simulation.
- **Not done:**
  - single control-plane instance;
  - A/B boot emulated in user space (no bootloader integration);
  - not deployed.

See [limitations](docs/limitations.md).

Key rotation (optional):

```bash
ROOT=$(./fleetctl keygen -out root.key); RELA=$(./fleetctl keygen -out rel-a.key)
./fleetctl keyset -root root.key -set-version 1 -ttl 720h -keys rel-a=$RELA -out ks1.json
./fleetd -data fleet-data -root-pubkey "$ROOT" -keyset ks1.json &          # devices: fleet-agent -root-pubkey "$ROOT" ...
./fleetctl release -key rel-a.key -key-id rel-a -version 2.0 -file app-v2
RELB=$(./fleetctl keygen -out rel-b.key)                                     # rotate, revoke rel-a
./fleetctl keyset -root root.key -set-version 2 -ttl 720h -keys rel-b=$RELB -revoke rel-a -out ks2.json
./fleetctl keyset-push -file ks2.json
```

## Results ([docs/benchmarks.md](docs/benchmarks.md))

| | |
|---|---|
| 2,000 devices, good release, waves 1/10/50/100 % | fleet fully updated in 10.4 s |
| Bad release (every trial fails) | halted at the canary after **15 of 2,000** devices tried it; all rolled back |
| Flaky release (3 % failures, 10 % limit) | completes; the 46 failed devices stay on the old version |
| Crash at every update step | device always bootable, then converges (tests) |
| Tampered artifact / unsigned upload / replayed request | rejected (tests) |
| Plain heartbeat load | ~1,800/s, p99 17 ms (4 vCPUs shared with 2,000 simulated devices) |

## Quick start

```bash
go build ./cmd/...
PUB=$(./fleetctl keygen -out release.key)
export FLEET_ADMIN_TOKEN=$(head -c 24 /dev/urandom | base64)
./fleetd -data fleet-data -release-pubkey "$PUB" -heartbeat-sec 5 &
./fleetctl release -key release.key -version 1.0 -file app-v1     # the version devices ship with
TOKEN=$(./fleetctl token | sed -n 's/.*"token": "\(.*\)".*/\1/p')
./fleet-agent -id dev-1 -state dev-1 -token "$TOKEN" -release-pubkey "$PUB" -exec &
./fleetctl release -key release.key -version 2.0 -file app-v2
./fleetctl rollout -version 2.0 -waves 10,50,100 -max-failure 0.1 -bake 10m
./fleetctl status <rollout-id>
```

An application is an executable that supports `app run` (the long-running service) and `app health` (exit 0 when healthy). Run `go test ./...` for the tests and `go run ./cmd/fleetsim -n 2000` for the fleet simulation.

## Documentation

- [Architecture, trust model, update state machine](docs/architecture.md)
- [Testing](docs/testing.md)
- [Benchmarks](docs/benchmarks.md)
- [Limitations](docs/limitations.md)
- [Requirements matrix](docs/requirements.md)

## Scorecard (2026-10-15, self-assessed)

| Score | /10 | Why not higher |
|---|---|---|
| Fresher-portfolio strength | 8 | Crash-safe A/B updates, staged rollouts and key rotation are well tested, but it has never run on real devices. |
| Engineering maturity | 7 | Crash-at-every-step, mutation-checked and real-binary tests; but one lock on the heartbeat path and no TLS. |
| Deployment readiness | 3 | Not deployed, no TLS, no bootloader integration, no HA, shared admin token. |
| Completion of intended scope | 7 | OTA, rollouts and release-key rotation done; TUF, device-key rotation and delta updates are not. |
