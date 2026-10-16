# Limitations

* **Heartbeat path serialisation.** Update results and version changes are fsynced to the journal while holding the store's global lock. At 2,000 devices and 1 s heartbeats this shows up as 0.6–1.4 s p95–p99 call latencies during a rollout. Group commit, or a lock-free soft-state path, is the obvious fix.
* **Single control-plane instance** with local-disk state: no high availability and no replication. The store is sized for tens of thousands of devices, not millions; the state lives in memory.
* **Full-image updates only:** no delta updates or compression. An artifact is one executable; there is no multi-file bundle format.
* **The health check is generic:** the process stays up and `app health` passes. Application-specific health metrics feeding the rollout gate (error rates, crash reports) are not implemented.
* **The A/B boot is emulated in user space.** The agent plays the bootloader's role, with its boot counter in `boot.json`. Real OS/firmware updates need integration with the platform's bootloader (U-Boot/GRUB) or a tool like RAUC/Mender. The state machine here is the same idea.
* **Key rotation covers release keys only, and is not TUF.**
  * Release-signing keys can be rotated and revoked through a root-signed key set (version, expiry, keys, revoked ids). Devices pin the root key.
  * The root key itself cannot be rotated; replacing it means re-provisioning devices.
  * There are no TUF roles (targets, snapshot, timestamp), no signature thresholds, and no delegation. One root signature decides.
  * The legacy single `-release-pubkey` mode is still available, and has no rotation.
  * Expiry uses the device's clock. A device with a clock far in the future refuses valid sets; one far in the past accepts expired ones. Devices have no secure time source.
  * A compromised control plane can still withhold a new key set (freeze), until the device's current set expires; after that the device installs nothing.
  * Device keys cannot be rotated or revoked.
* **Admin access** is a single shared bearer token: no RBAC, no audit log beyond the journal.
* **Small fleets with tiny canary percentages** can have an empty first wave. The gate then advances, and the next wave acts as the canary.
* **Not deployed;** no TLS termination is configured. Run behind a TLS proxy.
