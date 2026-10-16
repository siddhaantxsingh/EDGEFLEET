# Benchmarks

Produced by `go run ./cmd/fleetsim -n N -heartbeat 1s -out bench/results/2026-10-14/sim_N.json` and rendered by `python3 bench/report.py 2026-10-14`. One 4-vCPU VM runs the control plane and all simulated devices in one process. Devices talk to the control plane over real HTTP on loopback; they really download, hash and verify each 256 KiB artifact and persist their A/B state. Only the health outcome is simulated (`sim_health`).

## 2,000 devices, heartbeat every 1 s

Enrollment of all devices took 2.0 s. The final heap was 69 MB, and the journal held 1.5 MB before compaction.

| scenario | outcome | time | devices that tried it | heartbeats/s | call latency p50 / p95 / p99 | CPU cores |
|---|---|---|---|---|---|---|
| good release | completed; versions {'2.0': 2000} | 10.4 s | 2,000 | 1,829 | 1.0 / 633 / 905 ms | 1.50 |
| bad release (all trials fail) | halted (wave 0: 2 of 2 reporting devices failed (limit 10%)); versions {'2.0': 2000} | 1.4 s | 15 | 1,768 | 0.4 / 9 / 17 ms | 0.69 |
| flaky release (3% failures, 10% limit) | completed; versions {'2.0': 46, '4.0': 1954} | 10.0 s | 2,000 | 1,742 | 3.7 / 933 / 1436 ms | 1.55 |

## Reading the results

* **Blast radius.** The release whose every trial fails reached 15 of 2,000 devices (0.75 %) before the gate halted the rollout in its first (1 %) wave. Every one of those devices rolled itself back. Devices outside the canary never downloaded it.
* **Failures are contained.** In the flaky release, 3 % of trials fail, under the 10 % limit. The rollout completes, and the 46 devices that failed stay on the previous version; the server never retries them.
* **Call latency includes the update.** The latency column times the agent's whole `Beat()` call, so during a rollout it includes downloading, hashing and trial-booting the new release. The bad-release row is mostly plain heartbeats: p99 17 ms at about 1,800 heartbeats/s.
* **Known bottleneck.** Each update result and version change is fsynced to the journal while holding the store's lock, so heartbeats from devices reporting at the same moment queue behind those fsyncs. Group commit for journal writes would remove this; see [limitations](limitations.md).
* **Small fleets and tiny waves.** With 1 % waves on 200 devices, the first wave can be empty. The gate then advances, and the 10 % wave becomes the effective canary (fleetsim at 200 devices: 20 devices reached). Choose wave sizes that put several devices in the first wave.

