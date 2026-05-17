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

84 malicious versions across 42 `@tanstack` packages were published using TanStack's own CI pipeline after an attacker poisoned the GitHub Actions build cache and extracted an OIDC token from runner memory. The payload carried **valid SLSA Build Level 3 provenance attestations** — the first time in documented supply chain history that a malicious package carried cryptographically valid build provenance.

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

## Compatibility

Shadow is **Linux only**. It uses Linux-specific kernel APIs — `clone()` with namespace flags, `pivot_root`, and eBPF — that have no equivalent on macOS or Windows. There is no port path without rebuilding from scratch using completely different primitives.

### Three hard requirements

All three must be satisfied before Shadow will run:

**1. Linux kernel 5.8+**
The eBPF Ring Buffer used for event streaming requires kernel 5.8 minimum.

**2. `CONFIG_BPF_LSM=y` compiled into the kernel**
```bash
cat /boot/config-$(uname -r) | grep CONFIG_BPF_LSM
# Must show: CONFIG_BPF_LSM=y
```

**3. `bpf` active in the LSM list at boot**
Even if compiled in, eBPF LSM hooks only fire if `bpf` is listed as an active LSM module at boot:
```bash
cat /sys/kernel/security/lsm
# Must contain "bpf" e.g.: ndlock,lockdown,yama,integrity,apparmor,bpf
```

If `bpf` is missing from the LSM list, add it to GRUB:
```bash
sudo nano /etc/default/grub
# Append "bpf" to GRUB_CMDLINE_LINUX:
# lsm=ndlock,lockdown,yama,integrity,apparmor,bpf

sudo update-grub && sudo reboot
```

### Distro compatibility

| Distro | Kernel | Works | Notes |
|---|---|---|---|
| Ubuntu 24.04 LTS | 6.8 | ✅ Yes | BPF LSM active by default |
| Fedora 39+ | 6.5+ | ✅ Yes | Ships with BPF LSM active |
| Arch Linux | Rolling (6.x) | ✅ Yes | Fully supported |
| Kali Linux | Rolling | ✅ Yes | BPF LSM active |
| Ubuntu 22.04 LTS | 5.15 | ⚠️ Partial | Needs one-time GRUB edit |
| Debian 12 (Bookworm) | 6.1 | ⚠️ Partial | Needs one-time GRUB edit |
| Linux Mint 21 | 5.15 | ⚠️ Partial | Ubuntu 22.04 base — needs GRUB edit |
| RHEL 9 / Rocky 9 | 5.14 backport | ❌ No | `CONFIG_BPF_LSM` disabled |
| RHEL 8 / Rocky 8 | 4.18 backport | ❌ No | Kernel too old |
| Amazon Linux 2 | 5.10 | ❌ No | `CONFIG_BPF_LSM` not enabled |
| CentOS Stream 9 | 5.14 | ❌ No | Same as RHEL 9 |
| macOS | — | ❌ No | No Linux namespace or eBPF support |
| Windows | — | ❌ No | No Linux namespace or eBPF support |

> RHEL/CentOS/Amazon Linux don't work because enterprise distros disable bleeding-edge kernel features for stability. Fixing this requires CO-RE (Compile Once, Run Everywhere) portability work — planned but not yet implemented.

### Quick compatibility check

Run this before building:
```bash
echo "=== Shadow Compatibility Check ===" && \
echo "Kernel: $(uname -r)" && \
echo "BTF: $(ls /sys/kernel/btf/vmlinux 2>/dev/null && echo OK || echo MISSING)" && \
echo "BPF_LSM: $(cat /boot/config-$(uname -r) 2>/dev/null | grep CONFIG_BPF_LSM || echo NOT FOUND)" && \
echo "LSM list: $(cat /sys/kernel/security/lsm 2>/dev/null || echo NOT FOUND)"
```

All four lines should show kernel 5.8+, BTF OK, `CONFIG_BPF_LSM=y`, and an LSM list containing `bpf`.

---

## Building from Source

**Dependencies:**

```bash
# Ubuntu / Debian
sudo apt install clang bpftool libbpf-dev libelf-dev cmake build-essential

# Fedora
sudo dnf install clang bpftool libbpf-devel elfutils-libelf-devel cmake gcc-c++

# Arch
sudo pacman -S clang bpf libbpf cmake
```

**Build:**

```bash
git clone https://github.com/aadesh006/Shadow-Analyzer
cd Shadow-Analyzer
mkdir build && cd build
cmake ..
make
```

The build pipeline:
1. `clang` compiles `shadow.bpf.c` to eBPF bytecode targeting the BPF architecture
2. `bpftool gen skeleton` generates the C++ skeleton header used to load and attach programs
3. `cmake` compiles and links the C++ host binary against `libbpf`, `libelf`, `libz`

---

## Usage

```bash
sudo ./shadow analyze <package>
sudo ./shadow analyze <package>@<version>

# Examples
sudo ./shadow analyze lodash
sudo ./shadow analyze axios@1.14.1
sudo ./shadow analyze esbuild
sudo ./shadow analyze sharp
```

Shadow must be run as root. Analysis completes in the time npm takes to install the package (1–30 seconds). If the package stalls, Shadow kills the sandbox after 60 seconds.

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
CLEAN     → No threats detected. Safe to install.
MALICIOUS → Definitive threat detected. Do not install.
TIMEOUT   → Package stalled analysis. Manual review required.
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

**Root required.** `clone()` with namespace flags and eBPF program loading both require root.

**Linux only.** macOS and Windows are not supported and there is no port path without rebuilding from scratch.

**Not all Linux distros are supported.** RHEL, CentOS, Amazon Linux 2, and similar enterprise distros ship kernels with `CONFIG_BPF_LSM` disabled. See the compatibility table above.

**npm only.** pip/PyPI support is planned.

**Network connections observed but not blocked.** `CLONE_NEWNET` is not yet enabled. Shadow classifies outbound connections but does not block them at the network level. A malicious package can still exfiltrate data during the analysis window.

**LSM hooks are host-global.** The eBPF LSM hook watches all processes on the host, not just the sandbox. Host system processes that read credential files during the analysis window can cause false positive MALICIOUS verdicts. PID-scoped filtering is in progress.

**Staged payloads.** A package that behaves cleanly during the analysis window will not be caught. Fundamental limitation of dynamic analysis.

**Early stage, single developer.** Shadow is built by one person still learning kernel-level programming. There are likely bugs and gaps that haven't been found yet. That's part of why it's open source.

---

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Core sandbox + eBPF LSM + unified verdict engine + `analyze` CLI | **In progress** |
| Phase 2 | `CLONE_NEWNET` network isolation, PID-scoped LSM filtering, `shadow diff` (OverlayFS) | Next |
| Phase 3 | `shadow watch` continuous EDR daemon, `shadow policy sync` remote threat feeds | Planned |
| Phase 4 | pip/PyPI support, GitHub Actions integration, CO-RE portability for RHEL/Amazon Linux | Planned |

---

## Contributing

Shadow is early-stage and built by one person who is still learning kernel-level development. Contributions are genuinely welcome — especially from people who know this space better than I do.

**Rules and intelligence** — most accessible starting point, no kernel knowledge required:
- Additional entries for `shadow_rules.conf` (sensitive file paths Shadow should block)
- Entries for `threat_intel.cpp` `is_malicious()` (known C2 domains and IPs)
- Entries for `is_trusted_cdn()` (legitimate CDN destinations that should not be flagged)

**Code review** — where experienced eyes are most needed:
- The eBPF LSM hook implementation — edge cases I haven't covered
- The `pivot_root` sandbox construction — potential escape vectors
- The namespace setup — correctness of `CLONE_NEWUSER` UID/GID mapping
- Anything that looks wrong to someone with kernel experience

**Testing:**
- Running Shadow on distros not in the compatibility table and reporting results
- Testing with packages that have complex postinstall scripts
- Finding false positives on legitimate packages

Bug reports with the full Shadow output and your kernel version (`uname -r`) are extremely helpful.

```bash
git clone https://github.com/aadesh006/Shadow-Analyzer
cd Shadow-Analyzer
mkdir build && cd build
cmake .. && make
sudo ./shadow analyze lodash   # should return CLEAN in ~1s
sudo ./shadow analyze esbuild  # should return CLEAN with CDN traffic logged
```

---

## Background

Shadow was built in response to the axios npm supply chain attack (March 2026). The only tool that caught that attack in CI was StepSecurity Harden-Runner — an enterprise-grade GitHub Actions product. There was no open-source, developer-local equivalent that could analyze a package before installation using runtime behavioral analysis at the kernel level.

Shadow fills that gap. It is not finished, but the core is working and the problem it is solving is real.

---

## Author

**Aadesh Chaudhari**
GitHub: [@aadesh006](https://github.com/aadesh006)

*Built in response to the axios and TanStack npm supply chain attacks, 2026*
