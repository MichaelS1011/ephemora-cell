# Protected Linux Reference Environment

A concrete, reproducible **outer** security boundary for the Ephemora Cell
worker process. The WASI sandbox, worker `RLIMIT`s and resource budgets are the
**inner** wall that bounds the guest. This container is the **outer** wall the
worker process itself lives behind, so that a native fault or a worker-level
escape lands in a kernel-enforced boundary instead of on the host.

> A plain worker process is **not** sufficient proof of host isolation. This
> profile is the operating-system layer measured on top of it.

## What is here

| File | Role |
|---|---|
| `Dockerfile` | Fresh install of `ephemora-cell` from the built wheel into a digest-pinned `python:3.12-slim`, running as an unprivileged `cell` UID. |
| `run.sh` | The hardened `docker run` invocation — the reference flag set is documented inline. |
| `escape_probe.py` | Boundary negation tests run from a fully compromised-worker perspective. |
| `fixtures/` | Read-only test guests (`hello02.wasm`, `fs02.wasm`). No production data. |
| `context/` | Build context (the wheel + `requirements.lock`). Populate from `dist/` before building. |

## Reference boundary (the profile)

```
--network none                      OS-level egress kill (no netns route)
--read-only                         immutable rootfs
--cap-drop=ALL                      no Linux capabilities
--security-opt no-new-privileges    setuid/file-cap escalation blocked
--pids-limit 128                    fork-bomb ceiling (cgroup pids)
--memory 512m --memory-swap 512m    cgroup RSS ceiling
--cpus 1.0                          cgroup CPU bandwidth ceiling
--user 10001:10001                  dedicated unprivileged `cell` UID
--tmpfs /tmp:size=64m               bounded, ephemeral worker scratch
-v fixtures:/input:ro               the ONLY mounted path (read-only test data)
```

## What was measured, and where

The profile above is the profile that was **run**, unchanged, in two
environments:

| Environment | Runtime | Outcome |
|---|---|---|
| Docker Desktop 28.5.1 on macOS arm64 (container runs in a Linux VM) | `runc`, `linux/arm64` | 11 boundary tests held, 1 positive control, 0 leaks |
| **Native Linux** — Ubuntu 24.04.4, kernel `6.17.0-1032-nvidia`, `aarch64`, 20 CPUs / 121 GiB, Docker Engine 29.2.1, `runc` 1.3.4, cgroup v2, AppArmor `docker-default (enforce)` | `runc`, `linux/arm64` | 10 `BLOCKED`, 2 `ALLOWED` (1 tmpfs positive control + 1 cgroup self-read that is not resolvable from inside); enforcement confirmed host-side and behaviorally |

Evidence: `benchmarks/results/2026-10-13/` (`native_linux/` for the native run,
`release_identity.json` for the artifact→commit binding).

Two native-Linux deviations from the Docker Desktop measurement are recorded
rather than smoothed over:

- **cgroup self-inspection:** from inside the container the probe could not read
  its own `memory.max`/`pids.max` (the scope path is only visible host-side under
  `CgroupnsMode=host`). Limits were therefore verified **host-side**
  (`07_host_cgroup.txt`: `memory.max=536870912`, `pids.max=128`,
  `cpu.max=100000 100000`) **and behaviorally** (`08_enforcement.txt`: a 1 GiB
  allocation was OOM-killed with exit 137, `oom_kill=1`; forking stopped at 126
  children with `EAGAIN`; 4 spinners produced `nr_throttled=41` of 42 periods).
- **`--network none` still injects host resolver data:** `/etc/resolv.conf` in the
  container carried the host nameserver and search domain. Network egress is dead
  (`errno 101`, DNS resolution fails, raw sockets `EPERM`), but the container
  image's filesystem is **not** secret-free. Do not treat it as one, and do not
  bind-mount anything you would not want read there.

Neither run is, or is claimed to be, proof that the host kernel has no escape
vulnerability — see non-guarantees below.

## Reproduce

```bash
uv build --wheel --sdist                                   # -> dist/*.whl
cp dist/*.whl dist/*.tar.gz context/dist/                  # stock the context
docker build -f Dockerfile -t "ephemora-cell-ref:$(./run.sh tag)" context
bash run.sh probe                                          # boundary negation tests
printf '%s' '{"config":{"max_fuel":5000000,"timeout_seconds":30,"io_cpu_seconds":2.0}}' \
  | bash run.sh worker                                     # protected component run
# bind the artifacts you just tested to the commit you tested:
python scripts/release_identity.py --check-pypi --out benchmarks/results/release_identity.json
```

On a native Linux host, run steps 3–6 there (not in Docker Desktop) and keep the
`01_host_facts` / `07_host_cgroup` / `08_enforcement` outputs — the point of the
native measurement is that the guards are checked against the real kernel and
the real cgroup tree, not a VM's approximation of them.

## Explicit non-guarantees

- `runc` shares the host **Linux kernel**; a kernel privilege-escape is outside
  this profile. Multi-tenant production needs a gVisor/Firecracker tier (stronger
  isolation, separate measurement).
- The native-Linux run above is a **reference-environment verification**, not a
  kernel-security audit: it measures that the documented OS guards are actually
  active and effective on a real Linux host. It says nothing about the absence of
  kernel vulnerabilities, and the host used was **not single-tenant** (unrelated
  containers and daemons were running; the profile does not see them, but the
  kernel they share is the same one).
- `--pids-limit`/`--memory`/`--cpus` are per-container ceilings; they do not
  replace the per-guest fuel / I/O / time budgets enforced inside the worker.
- The probe proves the chosen OS boundaries hold against the tested vectors; it
  does not rank them as strongest, and attests nothing about guest output
  correctness.
