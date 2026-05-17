# Shadow
### npm Package Runtime Behavioral Sandbox

> **Two major supply chain attacks in 45 days. Both bypassed every static analysis tool. Shadow is built to catch them.**

Shadow is an open-source Linux security tool that runs npm packages inside a kernel-level isolated sandbox before you install them. Where existing tools analyze source code, Shadow observes what a package **actually does at runtime** — every file it opens, every process it spawns, every network connection it attempts — intercepted at Ring 0 before your system is touched.

```
=== Shadow Analyzer v1.0 ===
[Shadow] Target: axios@1.14.1

[Shadow] 6 rules injected into Ring 0 kernel map.
[eBPF]   Kernel probe attached. All hooks live.
[Shadow] Launching npm inside sandbox...

  ╔══════════════════════════════════════════╗
  ║       LSM THREAT BLOCKED AT RING 0       ║
  ╚══════════════════════════════════════════╝
  Process:  node (PID 4821)
  Attempted: read credentials
  Result:    EPERM — file never opened
  Latency:   0ms (Ring 0 native block)

  [ALERT] Suspicious process spawned during install: /usr/bin/curl
  [NET]   PID: 4821 -> 185.220.101.47 Port: 4444

[Shadow] ══════════════ ANALYSIS COMPLETE ══════════════
[RESULT] MALICIOUS — Credential access blocked: credentials
         DO NOT INSTALL THIS PACKAGE.
```

---

## Why Shadow Exists

### The axios attack (March 31, 2026)

A threat actor compromised the npm account of the primary axios maintainer and published two malicious versions — `axios@1.14.1` and `axios@0.30.4` — with a RAT dropper injected as a transitive dependency (`plain-crypto-js`). The malware:

- Connected to a C2 server (`sfrclak.com`) within 2 seconds of `npm install`
- Harvested credentials, SSH keys, and environment variables
- Deleted itself after execution to leave no trace
- Was live for **2 hours 54 minutes** before removal

### The TanStack attack (May 11, 2026)

84 malicious versions across 42 `@tanstack` packages were published using TanStack's own CI pipeline after an attacker poisoned the GitHub Actions build cache and extracted an OIDC token from runner memory. The payload carried **valid SLSA Build Level 3 provenance attestations** — a first in documented supply chain attacks.

### What every tool missed

| Tool | Approach | Axios | TanStack |
|---|---|---|---|
| npm audit | CVE database lookup | ❌ No CVE existed | ❌ No CVE existed |
| Snyk / Dependabot | Static dependency graph | ❌ Source unchanged | ❌ Source unchanged |
| GitHub secret scanning | Regex on source files | ❌ Payload obfuscated | ❌ Triple-layer obfuscation |
| SLSA / provenance | Build attestation | ❌ Account compromised | ❌ Valid attestation on malicious build |
| Falco | Runtime EDR (production servers) | ❌ Not on dev machines | ❌ Not on dev machines |
| Socket.dev | Static AST analysis | ❌ Runtime-only payload | ❌ Encrypted payload |
| **Shadow** | **Runtime behavioral sandbox** | **✅ C2 + credential access** | **✅ Persistence + credential access** |

Shadow catches what every other tool misses: behavior that only appears at runtime, encrypted payloads that reveal themselves during execution, and novel attack techniques with no known CVE.

---

## How It Works

Shadow runs in two privilege rings simultaneously:

```
┌─────────────────────────────────────────────────────────────┐
│  Ring 3 — C++ Userspace Engine                              │
│                                                             │
│  Observer (observer.cpp)                                    │
│  ├── Ring buffer consumer — reads kernel events in realtime │
│  ├── ThreatIntel — CDN allowlist + known C2 classification  │
│  └── Verdict engine — unified MALICIOUS / CLEAN decision    │
│                                                             │
│  Sandbox (sandbox.cpp)                                      │
│  ├── Linux namespaces (PID, MNT, UTS, IPC, USER)           │
│  ├── pivot_root filesystem jail                             │
│  └── Identity downgrade (root → nobody inside jail)        │
├─────────────────────────────────────────────────────────────┤
│  Ring 0 — eBPF Kernel Programs (shadow.bpf.c)              │
│                                                             │
│  LSM hook (lsm/file_open)                                   │
│  └── Blocks credential file reads natively — 0ms latency   │
│      Populated from shadow_rules.conf via eBPF Hash Map     │
│                                                             │
│  Tracepoint (sys_enter_execve)                              │
│  └── Tracks every process spawned by the package           │
│                                                             │
│  Tracepoint (sys_enter_connect)                             │
│  └── Captures every outbound network connection attempt     │
└─────────────────────────────────────────────────────────────┘
```

### The Sandbox

Each analysis run uses `clone()` with namespace isolation flags to create a jailed child process. Inside the namespace:

- `pivot_root` severs the process from the real filesystem — it cannot see or write to your actual disk
- `/tmp` is a fresh `tmpfs` RAM disk — all package writes go here and are discarded on exit
- `CLONE_NEWUSER` maps sandbox root to an unprivileged UID on the host — root inside the jail is nobody outside it
- `HOME` is forced to `/tmp`, `PATH` is restricted, no ambient capabilities

The package is born already being watched. There is no startup gap between sandbox creation and kernel hook attachment.

### The eBPF LSM Hook (Phase 4 — Ring 0 Blocking)

The LSM hook is Shadow's core defensive capability. Unlike passive tracepoints that observe after the fact, the `lsm/file_open` hook intercepts file access **before the kernel grants it**.

When a package attempts to read `/etc/shadow`, `~/.ssh/id_rsa`, `~/.aws/credentials`, or any other entry in `shadow_rules.conf`:

1. The kernel reaches the LSM enforcement point
2. Shadow's eBPF program runs — JIT-compiled Ring 0 machine code
3. The filename is looked up in a live eBPF Hash Map
4. If matched: `return -EPERM` — the file is never opened
5. An alert event is pushed to the ring buffer
6. The C++ engine receives it and sets `threat_detected = true`

Total latency: nanoseconds. The file contents are never read. No TOCTOU race condition.

### Dynamic Threat Intelligence

`shadow_rules.conf` contains the blocked filename list. Rules are pushed into the kernel's eBPF Hash Map at startup via `bpf_map_update_elem()`. Adding a new rule takes effect instantly without recompiling or restarting Shadow.

```
# shadow_rules.conf
passwd
shadow
credentials
id_rsa
id_ed25519
.env
```

### Why Not Docker?

Docker adds a daemon dependency and requires the container to start before observation begins — creating a window where the package process exists unmonitored. Shadow uses `clone()` directly so the eBPF observer is loaded into the kernel before the child process is created. The package is born already being watched, with zero startup gap and no daemon requirement.

Docker's overhead per syscall is also significantly higher. Shadow's eBPF tracepoints add ~50 nanoseconds per event. Docker's seccomp filtering adds ~10 microseconds — 200× slower.

---

## Current Status

| Component | Status |
|---|---|
| Linux namespace sandbox (PID, MNT, UTS, IPC, USER) | ✅ Working |
| `pivot_root` filesystem jail | ✅ Working |
| Identity downgrade (sandbox root → host nobody) | ✅ Working |
| eBPF execve tracepoint — process tree tracking | ✅ Working |
| eBPF connect tracepoint — network connection capture | ✅ Working |
| eBPF LSM `file_open` hook — credential file blocking | ✅ Working |
| Dynamic blocklist via eBPF Hash Map | ✅ Working |
| CDN allowlist (Cloudflare, npm, GitHub CDN) | ✅ Working |
| Known C2 domain/IP blocklist | ✅ Working |
| Suspicious process spawn detection (curl, wget, python) | ✅ Working |
| Sandbox execution timeout (60s) | ✅ Working |
| Unified MALICIOUS / CLEAN verdict | ✅ Working |
| Network namespace isolation (`CLONE_NEWNET`) | 🔧 In progress |
| PID-scoped LSM filtering (sandbox-only events) | 🔧 In progress |
| OverlayFS filesystem delta (`shadow diff`) | ⏳ Planned |
| `shadow watch` — continuous host EDR daemon | ⏳ Planned |
| `shadow policy sync` — remote threat feed | ⏳ Planned |
| pip / PyPI support | ⏳ Planned |
| GitHub Actions integration | ⏳ Planned |

---

## Building from Source

**Requirements:**

- Linux kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- Ubuntu 20.04+ or Debian 11+ recommended
- `clang` (for eBPF compilation)
- `bpftool` (for skeleton generation)
- `libbpf-dev`, `libelf-dev`
- `cmake` 3.10+, C++17 compiler
- Root — required for `clone()` with namespace flags and eBPF program loading

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install clang bpftool libbpf-dev libelf-dev cmake build-essential

# Build
git clone https://github.com/aadesh006/Shadow-Analyzer
cd Shadow-Analyzer
mkdir build && cd build
cmake ..
make
```

The build pipeline:
1. `clang` compiles `shadow.bpf.c` to eBPF bytecode targeting the BPF architecture
2. `bpftool gen skeleton` generates the C++ skeleton header used to load and attach the programs
3. `cmake` compiles and links the C++ host binary against `libbpf`, `libelf`, `libz`

**Verify BTF is available:**
```bash
ls /sys/kernel/btf/vmlinux
# Must exist. If not, BTF is not enabled in your kernel.
```

---

## Usage

```bash
# Analyze any npm package before installing
sudo shadow analyze <package>
sudo shadow analyze <package>@<version>

# Examples
sudo shadow analyze lodash
sudo shadow analyze axios@1.14.1
sudo shadow analyze esbuild
sudo shadow analyze sharp
```

Shadow must be run as root. The analysis completes in the time it takes npm to install the package (typically 1–30 seconds). If the package stalls or hangs, Shadow kills the sandbox after 60 seconds.

### Output Guide

```
[NET]        → Outbound connection to known CDN (safe)
[SUSPICIOUS] → Outbound connection to non-CDN destination
[THREAT]     → Connection to known malicious IP/domain
[PROCESS]    → Unexpected process spawned during install
[ALERT]      → Suspicious process spawned (curl, wget, bash, python)
LSM BLOCKED  → Credential file access denied natively in Ring 0
```

### Verdicts

```
CLEAN    → No threats detected. Safe to install.
MALICIOUS → Definitive threat detected. Do not install.
TIMEOUT  → Package stalled analysis. Manual review required.
```

---

## Architecture

```
Shadow-Analyzer/
├── CMakeLists.txt
├── shadow_rules.conf            # LSM blocklist — loaded into kernel at startup
└── core/
    ├── include/
    │   ├── observer.h           # eBPF loader + ring buffer + verdict engine
    │   ├── sandbox.h            # Linux namespace sandbox
    │   └── threat_intel.h       # CDN allowlist + C2 blocklist
    └── src/
        ├── main.cpp             # CLI entry point
        ├── observer.cpp         # libbpf skeleton, ring buffer, detection logic
        ├── sandbox.cpp          # clone(), pivot_root, identity downgrade
        ├── threat_intel.cpp     # IP/domain classification
        └── bpf/
            └── shadow.bpf.c     # eBPF kernel programs (LSM + tracepoints)
```

---

## Technology Stack

| Component | Technology |
|---|---|
| Sandbox orchestrator | C++17 |
| eBPF kernel programs | C (clang BPF backend) |
| eBPF loader | libbpf skeleton API |
| Threat blocking | eBPF LSM hooks (`lsm/file_open`) |
| Event streaming | eBPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`) |
| Dynamic rules | eBPF Hash Maps (`BPF_MAP_TYPE_HASH`) |
| Build system | CMake |

---

## Known Limitations

**Root required.** `clone()` with namespace flags and eBPF program loading both require root. Rootless support is on the roadmap.

**Linux only.** Shadow uses Linux-specific APIs (eBPF, Linux namespaces, `pivot_root`). macOS and Windows are not supported.

**Linux kernel 5.8+ required.** eBPF LSM hooks require kernel 5.8+ with `CONFIG_BPF_LSM` enabled. Ubuntu 20.04+ works out of the box.

**npm only.** pip/PyPI support is planned for Phase 2.

**Network connections observed but not blocked.** `CLONE_NEWNET` is not yet enabled. Shadow detects outbound connections and classifies them but does not block them at the network level. A malicious package can still exfiltrate data during the analysis window if it reaches a non-blocked IP. This is the next item on the roadmap.

**LSM hooks are host-global.** The eBPF LSM hook watches all processes on the host, not just the sandbox. Host system processes (pkexec, polkitd, update-notifier) that read credential files during the analysis window can cause false positive MALICIOUS verdicts. PID-scoped filtering is in progress.

**Staged payloads.** A package that detects it is being analyzed and behaves cleanly during the observation window will not be caught. This is a fundamental limitation of dynamic analysis with a fixed time window.

---

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Core sandbox + eBPF LSM + unified verdict engine + `analyze` CLI | **In progress** |
| Phase 2 | `CLONE_NEWNET` network isolation, PID-scoped LSM filtering, `shadow diff` (OverlayFS) | Next |
| Phase 3 | `shadow watch` continuous EDR daemon, `shadow policy sync` remote threat feeds | Planned |
| Phase 4 | pip/PyPI support, GitHub Actions integration, VS Code extension | Planned |

**Immediate next steps:**
- Enable `CLONE_NEWNET` to isolate sandbox network stack
- Implement PID-scoped LSM filtering to eliminate host process false positives
- Add OverlayFS filesystem delta (`shadow diff`) to show exactly what files a package drops

---

## Contributing

Shadow is early-stage and contributions are welcome. The most useful contributions right now:

- Additional entries for `shadow_rules.conf` (sensitive file paths)
- Entries for `threat_intel.cpp` `is_malicious()` (known C2 domains and IPs)
- Testing on different Linux distributions and kernel versions
- Bug reports with full output

```bash
git clone https://github.com/aadesh006/Shadow-Analyzer
cd Shadow-Analyzer
mkdir build && cd build
cmake .. && make
sudo ./shadow analyze lodash   # should return CLEAN
```

---

## Background

Shadow was built in response to the axios npm supply chain attack (March 2026). The only tool that caught that attack in CI — StepSecurity Harden-Runner — is an enterprise-grade GitHub Actions product costing hundreds of dollars per month. There was no open-source, developer-local equivalent that could analyze a package before installation using runtime behavioral analysis.

Shadow fills that gap.

---

## Author

**Aadesh Chaudhari**
GitHub: [@aadesh006](https://github.com/aadesh006)

*Built in response to the axios and TanStack npm supply chain attacks, 2026*