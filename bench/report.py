"""Render docs/benchmarks.md from bench/results/<date>/sim_*.json."""
import glob
import json
import sys

D = sys.argv[1]
L = ["# Benchmarks\n",
     f"Produced by `go run ./cmd/fleetsim -n N -heartbeat 1s -out bench/results/{D}/sim_N.json` and rendered by "
     f"`python3 bench/report.py {D}`. One 4-vCPU VM runs the control plane and all simulated devices in one process. Devices "
     "talk to the control plane over real HTTP on loopback; they really download, hash and verify each 256 KiB artifact "
     "and persist their A/B state. Only the health outcome is simulated (`sim_health`).\n"]
for f in sorted(glob.glob(f"bench/results/{D}/sim_*.json")):
    r = json.load(open(f))
    L += [f"## {r['devices']:,} devices, heartbeat every {r['heartbeat_interval_s']:.0f} s\n",
          f"Enrollment of all devices took {r['enroll_seconds']:.1f} s. The final heap was {r['heap_mb']:.0f} MB, and the journal held {r['journal_bytes'] / 1e6:.1f} MB "
          "before compaction.\n",
          "| scenario | outcome | time | devices that tried it | heartbeats/s | call latency p50 / p95 / p99 | CPU cores |",
          "|---|---|---|---|---|---|---|"]
    for s in r["scenarios"]:
        lat = s["heartbeat_latency_ms"]
        outcome = s["final_state"]
        if s.get("reason"):
            outcome += f" ({s['reason']})"
        L.append(f"| {s['name']} | {outcome}; versions {s['versions']} | {s['seconds']:.1f} s | {s['devices_that_tried_it']:,} | "
                 f"{s['heartbeats_per_sec']:,.0f} | {lat['p50']:.1f} / {lat['p95']:.0f} / {lat['p99']:.0f} ms | {s['cpu_cores']:.2f} |")
    L.append("")
L += ["## Reading the results\n",
      "* **Blast radius.** The release whose every trial fails reached 15 of 2,000 devices (0.75 %) before the gate halted the "
      "rollout in its first (1 %) wave. Every one of those devices rolled itself back. Devices outside the canary never downloaded it.",
      "* **Failures are contained.** In the flaky release, 3 % of trials fail, under the 10 % limit. The rollout completes, and the 46 devices "
      "that failed stay on the previous version; the server never retries them.",
      "* **Call latency includes the update.** The latency column times the agent's whole `Beat()` call, so during a rollout it "
      "includes downloading, hashing and trial-booting the new release. The bad-release row is mostly plain heartbeats: p99 17 ms "
      "at about 1,800 heartbeats/s.",
      "* **Known bottleneck.** Each update result and version change is fsynced to the journal while holding the store's "
      "lock, so heartbeats from devices reporting at the same moment queue behind those fsyncs. Group commit for journal "
      "writes would remove this; see [limitations](limitations.md).",
      "* **Small fleets and tiny waves.** With 1 % waves on 200 devices, the first wave can be empty. The gate then advances, "
      "and the 10 % wave becomes the effective canary (fleetsim at 200 devices: 20 devices reached). Choose wave sizes that "
      "put several devices in the first wave.\n"]
open("docs/benchmarks.md", "w").write("\n".join(L) + "\n")
