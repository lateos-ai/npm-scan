# Sandbox Threat Model — npm-scan Dynamic Analysis

## Overview

The dynamic sandbox executes untrusted npm packages in an isolated environment to detect behavioral attacks (ATK-008–010). Escape would compromise the host, so isolation is the highest-priority design constraint.

## Isolation Stack

**Primary: gVisor (runsc)**
- Kernel-level syscall interception without a full VM
- Docker-compatible, production-hardened by Google
- Each analysis runs in a separate sandbox container

**Fallback: Firecracker microVMs**
- For highest-assurance / air-gapped environments
- Slower startup, stronger isolation boundary

**Explicitly excluded:**
- `vm2` — repeated CVEs (CVE-2023-29017, etc.), known escape surface
- `isolated-vm` — Node-based V8 isolate, insufficient for hostile native code

## Threat Model

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Syscall escape | Critical | gVisor intercepts all syscalls at kernel boundary; no uncontained syscalls reach host kernel |
| Network exfiltration during analysis | Critical | Network namespace isolation; egress blocked except to monitored sink/HTTPBun |
| Filesystem escape | High | Read-only bind mounts; package extracted to ephemeral tmpfs; no persistent mounts |
| Resource exhaustion (CPU/memory bomb) | Medium | cgroup limits: 1 CPU, 512MB RAM, 30s timeout; SIGKILL on timeout |
| Sandbox detection by malware | Medium | Randomized env vars, realistic process tree, no obvious sandbox markers in `/proc` |
| Tarball extraction bomb | Medium | Size limits enforced before extraction (uncompressed cap: 500MB) |
| Container escape via Docker socket | Critical | Sandbox containers get no Docker socket mount; `--privileged` never used |
| Filesystem write amplification | Low | tmpfs capped at 512MB; no disk-backed volumes |

## Network Isolation

- **Default mode:** Full egress blocked. Container has loopback only.
- **Monitor mode (opt-in):** Egress allowed through a MITM proxy (HTTPBun/sink) that records all requests for post-analysis review. The malware believes it has network access; actually all traffic is captured.

## Filesystem Layout

```
/tmp/analysis/{id}/
  ├── package/          # extracted tarball (read-only bind mount)
  ├── run.js            # runner script that executes the package
  └── output.json       # structured findings after timeout
```

## Timeouts and Lifecycle

1. Container starts → package extracted → 30s countdown begins
2. Runner runs `npm install && node index.js` (or entry point from package.json)
3. All syscalls logged via gVisor's `strace`-style logging
4. On timeout (30s): SIGKILL, logs collected, findings generated
5. Container destroyed, tmpfs unmounted

## Analysis Pipeline

```
  [fetch tarball] → [verify size < 500MB] → [extract to tmpfs]
       → [gVisor sandbox: execute entry point for 30s]
       → [collect syscall log + file system diffs]
       → [run ATK-008/009/010 behavioral detectors on trace]
       → [merge static + dynamic findings]
       → [cleanup: destroy container, unmount tmpfs]
```

## Anti-Sandbox-Evasion (ATK-010)

The analyzer checks for behaviors indicating the package probes its environment:

- Hostname checks (expects randomized, non-obvious hostnames)
- `CI` env var detection (sandbox should NOT set CI-like env vars)
- Timing attacks (`performance.now()`, `process.hrtime()`)
- Process tree inspection (`process.ppid`, `/proc/self/status`)
- Stack trace capture (Error().stack inspection)

Detection of evasion attempts is itself a high-severity finding.

## Threat Model Review Cadence

| Type | Frequency | Owner |
|------|-----------|-------|
| Full threat model review | Every major release (quarterly) | Security lead |
| gVisor CVE monitoring | Continuous (automated alerts) | DevOps |
| Sandbox escape test | Every PR adding a new ATK detector | CI pipeline |
| Penetration test | Annual (third-party) | External firm |

---

*This document is a living artifact. Update when: gVisor version changes, new ATK entries require dynamic analysis, or a CVSS 7+ CVE affects the isolation stack.*