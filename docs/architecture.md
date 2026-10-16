# Architecture

```
 fleetctl ──(admin token)──► fleetd ◄──(Ed25519-signed HTTP)── fleet-agent × N
   keygen, sign + upload      │                                    │
   rollouts, status           │ journal + snapshot                 │ boot.json, slots/a, slots/b
                              ▼                                    ▼
                      rollout controller                    A/B install, trial boot,
                      (waves, gates, halt)                  health check, rollback
```

## Trust model

* **Release key.** Kept offline by the operator (`fleetctl keygen`). `fleetd` accepts an upload only if the signature verifies with the configured public key. Agents pin the same public key and verify the signature *and* the SHA-256 of the downloaded bytes before installing. A compromised control plane can therefore withhold or delay updates, but cannot make a device run unsigned code. The tests modify a stored artifact after upload, and the agents reject it.
* **Release-key rotation (optional, `-root-pubkey`).** Instead of one pinned release key, devices pin an offline **root key**. The root signs a **key set**: a version, an expiry time, the valid release keys (by id) and the revoked ids (`fleetctl keyset`). `fleetd` serves the current set in every heartbeat reply, and `fleetctl keyset-push` rotates it.
  * A device accepts a key set only if the root signature verifies, it has not expired by the device's clock, its version is not lower than the trusted one, an equal version is byte-identical, and it keeps every earlier revocation.
  * A device installs a release only if the key named by the release's key id is in its trusted, unexpired set and not revoked. The accepted set is saved before use, so a restart keeps the version floor.
  * The server applies the same checks to uploads, but devices do not rely on that: the tests serve revoked-key signatures and an old key set through a tampering proxy, and the devices refuse both.
* **Device identity.** At first start, the agent generates an Ed25519 key pair and enrolls with a **single-use** bootstrap token issued through the admin API.
  * Every later request is signed over `method, path, timestamp, nonce, SHA-256(body)`.
  * The server rejects unknown devices, bad signatures, timestamps more than ±5 min off, and reused nonces.
* **Admin API.** Bearer token, compared in constant time.

## Control plane (`fleetd`)

* **Durable state** lives in a CRC-checked append-only journal, fsynced per event, plus periodic atomic snapshots.
  * The journal holds tokens, enrollments, releases, rollout transitions, update results and confirmed versions.
  * A torn last line is truncated on start-up; corruption earlier in the journal is an error (tested at every byte).
  * Liveness (last heartbeat, state, metrics) is soft state kept in memory.
* **Heartbeat.** The device reports its active version, state, and the result of its last update (exactly once: the agent keeps it on disk until the server accepts the heartbeat). The response is the *desired* version, with the signed manifest and an artifact URL.
* **Artifacts** are served with HTTP Range support, so interrupted downloads resume (tested: only the missing half is sent).
* **Rollouts.**
  * Waves are cumulative percentages, for example 1/10/50/100.
  * Membership is a deterministic hash of (rollout id, device id), so it never changes during a rollout, survives restarts without being stored, and picks different canaries for each rollout.
  * The controller ticks every second and evaluates the current wave:
    * **halt** if failures / reports > `max_failure_rate`;
    * **wait** until `min_report_fraction` of the wave has reported and `bake_ms` has passed;
    * then **advance**, or **complete** after the last wave.
  * A halted or aborted rollout makes every device that took the new version roll back to `from_version`. Creating a rollout fails if no release exists to roll back to.
  * A device whose trial failed is never retried.
  * Pause stops new updates; resume continues; only one rollout can be active at a time.

## Agent (`fleet-agent`)

The device stays bootable after a crash at any step; this is tested by crashing at every step:

1. Download into the **inactive** slot as `app.part`, resuming with Range. Verify the signature and digest, then rename it to `app`.
2. Persist `trial = {slot, version, attempts}` in `boot.json` (temp file, fsync, rename, fsync dir). The active slot is untouched.
3. Boot the trial: persist `attempts + 1`, start the new app, and health-check it. The app must stay up for the health window and `app health` must exit 0.
4. If healthy: active = trial slot, and a success result is pended. If not: the old app is restarted, and a failure result (rolled back) is pended.

On start, a trial with `attempts ≥ 2` means repeated crashes during trial boots. The agent rolls back, like a bootloader boot counter. Rolling back to a version that the inactive slot still holds reuses the slot without downloading.
