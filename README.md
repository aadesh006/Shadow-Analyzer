# Shadow
### Dependency Runtime Behavior Analyzer

> **Every static analysis tool missed the axios attack. Shadow is being built to catch it.**

Shadow is an open-source runtime behavioral sandbox for npm packages. Where existing tools (npm audit, Snyk, Dependabot) rely on static CVE databases, Shadow runs the package inside an isolated Linux namespace, traces every syscall it makes with strace, and simultaneously hooks into the kernel via eBPF to observe network connections — before your system is touched.

```
=== Shadow Analyzer v1.0 ===
[Shadow] Target: axios@1.14.1

[Shadow] Spawning isolated namespaces
[Shadow] Sandbox created. Host mapped PID: 1842
[eBPF]   Kernel probe attached successfully.
  [KERNEL TRIGGER] PID: 1842 | IPv4 Target: 185.220.101.47
[Shadow] Sandbox execution completed.
[Shadow] --- Starting Heuristic Analysis ---
  [CRITICAL] Credential harvesting attempt: openat(AT_FDCWD, "/proc/self/environ", ...)
  [ALERT]    Suspicious shell execution detected: execve("/bin/sh", ...)
[Shadow] Analysis complete. Processed 312 system calls.

[RESULT] CRITICAL RISK DETECTED. INSTALLATION BLOCKED.
```

---

## Why Shadow Exists

On **March 31, 2026**, a threat actor compromised the npm account of the primary axios maintainer and published two malicious versions (`axios@1.14.1`, `axios@0.30.4`) with a RAT dropper injected as a transitive dependency. The malware called home to a C2 server within 2 seconds of `npm install`, harvested credentials and environment variables, then deleted itself — leaving no trace.

**npm audit reported nothing. Snyk reported nothing. The malicious versions were live for 2 hours 54 minutes.**

Shadow catches this class of attack by observing what a package *actually does at runtime*, not what its source code claims to do.

| Tool | Approach | Catches axios attack? |
|---|---|---|
| npm audit | CVE database lookup | ❌ No CVE existed |
| Snyk / Dependabot | Static dependency graph | ❌ Source code was unchanged |
| GitHub secret scanning | Regex on source files | ❌ Payload was obfuscated |
| SLSA / provenance | Build attestation | ❌ Token theft bypasses it |
| **Shadow** | **Runtime syscall observation** | **✅ C2 call and env harvesting detected** |

---

## Current Status

> ⚠️ **Shadow is in active early development.** The core sandbox and analysis engine are functional. eBPF observation and the strace parser are implemented as two parallel pipelines that are not yet unified into a single risk output.

| Component | Status |
|---|---|
| Linux namespace sandbox (PID + MNT) | ✅ Working |
| `strace`-based syscall tracing | ✅ Working |
| Heuristic parser (file + exec) | ✅ Working |
| eBPF network observer (kernel-side) | ✅ Working |
| Network heuristic risk scoring | 🔧 Detected but not scored yet |
| eBPF + Parser unified risk output | 🔧 Running in parallel, not integrated |
| Network namespace isolation (`CLONE_NEWNET`) | 🔧 Disabled (in progress) |
| cgroup CPU/memory limits | 🔧 Stub only |
| `diff` / `watch` / `scan` commands | ⏳ Planned |
| pip / PyPI support | ⏳ Planned |
| YAML policy rules | ⏳ Planned |
| GitHub Actions integration | ⏳ Planned |

---

## Building from Source

**Requirements:**

- Linux kernel 5.8+ with BTF enabled (Ubuntu 20.04+, Debian 11+)
- `clang`, `bpftool`, `libbpf-dev`, `libelf-dev`
- `strace`
- CMake 3.10+, C++17 compiler
- Must run as root (for `clone()` with namespace flags and eBPF loading)

```bash
git clone https://github.com/aadesh006/Shadow-Analyzer
cd Shadow-Analyzer
mkdir build && cd build
cmake ..
make
```

The build process:
1. Compiles `shadow.bpf.c` to eBPF bytecode with clang targeting BPF
2. Generates the C++ skeleton header via `bpftool gen skeleton`
3. Compiles and links the C++ host binary against `libbpf`, `libelf`, `libz`

---

## Usage

### Analyze an npm package

```bash
sudo ./shadow analyze <package>@<version>

sudo ./shadow analyze axios@1.14.1
sudo ./shadow analyze lodash@4.17.21
```

This is the only command currently implemented. `diff`, `watch`, and `scan` are planned for Phase 2.

---

## How It Works

Shadow is built in three active layers:

```
┌─────────────────────────────────────────────────────┐
│  Analysis Layer                                     │
│  Heuristic Parser (strace log) | eBPF Event Stream  │
├─────────────────────────────────────────────────────┤
│  Observation Layer                                  │
│  strace (execve, openat, connect) | eBPF ring buf   │
├─────────────────────────────────────────────────────┤
│  Sandbox Layer                                      │
│  Linux Namespaces (PID, MNT) | tmpfs | /proc isol.  │
└─────────────────────────────────────────────────────┘
```

### Sandbox (`sandbox.cpp`)

Each analysis run uses `clone()` with `CLONE_NEWPID | CLONE_NEWNS` to create an isolated child process. Inside the namespace:

- All mounts are made private (`MS_REC | MS_PRIVATE`)
- A fresh `/proc` is mounted for PID namespace isolation
- `tmpfs` is mounted over `/tmp` (500MB RAM disk) — the package writes here, not to your real filesystem
- `HOME` is forced to `/tmp` so npm believes its home directory is the RAM disk
- `PATH` is restricted to standard system directories

The target package is run via `strace -f -ff -e trace=execve,openat,connect -o shadow_trace.log npm install <package>`, capturing a full syscall trace to disk for the parser.

> **Note:** Network namespace isolation (`CLONE_NEWNET`) is currently disabled while the eBPF network observer is being integrated. Outbound connections are observed but not yet blocked at the network level.

### eBPF Observer (`observer.cpp` + `shadow.bpf.c`)

An eBPF program is compiled to BPF bytecode and loaded into the kernel via libbpf before the sandboxed process starts. It attaches to `tracepoint/syscalls/sys_enter_connect` and intercepts all outbound network connection attempts, writing events to a 256KB ring buffer.

The host-side observer runs a background polling thread that reads from the ring buffer and prints the destination IP and PID for every connection the package attempts — regardless of whether the package tries to hide it.

Currently captures:
- IPv4 connections: destination IP + port
- IPv6 connections: destination port (IP extraction pending)

### Heuristic Parser (`parser.cpp`)

After the sandbox completes, the strace log is parsed line-by-line through three heuristic checks:

| Heuristic | What it detects | Risk added |
|---|---|---|
| `checkFileHeuristic` | `openat` on `.ssh`, `/proc/self/environ`, `/etc/shadow` | +100 (immediate CRITICAL) |
| `checkExecutionHeuristic` | `execve` spawning `/bin/sh`, `curl`, or `wget` | +50 |
| `checkNetworkHeuristic` | `connect` with `AF_INET` — extracts destination IP | Detected, not yet scored |

Risk is evaluated on the **worst accumulated score**:

| Score | Result |
|---|---|
| ≥ 100 | `CRITICAL` — install blocked |
| > 0 | `HIGH` — suspicious behavior found |
| 0 | `CLEAN` — no suspicious behavior |

> **Known gap:** The network heuristic detects outbound connections but currently does not add to the risk score. This will be fixed in an upcoming commit to unify the eBPF and strace observation paths.

### Why not Docker?

Docker adds a daemon dependency and a ~50ms startup blind spot where the package process exists before observation begins. Shadow uses `clone()` directly so the eBPF observer is loaded into the kernel before the child process is ever created — the package is born already being watched, with no startup gap and no daemon requirement.

---

## Architecture & File Structure

```
shadow-analyzer/
├── CMakeLists.txt              # Build system (eBPF compile + C++ link)
└── core/
    ├── bpf/
    │   └── shadow.bpf.c        # eBPF kernel program (connect tracepoint)
    ├── include/
    │   ├── observer.h          # eBPF loader + ring buffer class
    │   ├── parser.h            # strace log analyzer class
    │   └── sandbox.h           # Linux namespace sandbox class
    └── src/
        ├── main.cpp            # CLI entry point (analyze command)
        ├── observer.cpp        # libbpf skeleton loader, background poll thread
        ├── parser.cpp          # Heuristic analysis of strace log
        ├── sandbox.cpp         # clone(), namespace setup, strace wrapping
        └── bpf/
            └── shadow.bpf.c    # (build output location for eBPF bytecode)
```

---

## Technology Stack

| Component | Technology |
|---|---|
| Sandbox orchestrator | C++ 17 |
| eBPF kernel programs | C (clang + BPF backend) |
| eBPF loader | libbpf (skeleton API) |
| Syscall tracing | strace |
| Build system | CMake |

---

## Known Limitations

- **Root required.** `clone()` with namespace flags and eBPF loading both require root. Rootless support is on the roadmap.
- **Linux kernel 5.8+ required** for eBPF/BTF. Ubuntu 18.04 and earlier are not supported.
- **npm only.** pip/PyPI support is planned for Phase 2.
- **Network isolation is disabled.** `CLONE_NEWNET` is commented out while the eBPF observer is being integrated. The sandbox does not currently block outbound connections.
- **eBPF and strace outputs are parallel, not unified.** Both observe behavior independently; they are not yet feeding into a single risk engine.
- **Network risk not scored.** Outbound connections are detected and printed by both observers but do not currently contribute to the risk score that determines install blocking.
- **Staged payloads** that behave cleanly during a short analysis window will not be caught.
- **macOS is not supported.** DTrace support is planned but not implemented.
- **Windows is not supported.** WSL2 may work for local use.

---

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| Phase 1 (Weeks 1–6) | Core sandbox, eBPF observer, strace parser, unified risk engine, `analyze` CLI | **In progress** |
| Phase 2 (Weeks 7–12) | `diff` / `watch` / `scan` commands, pip support, GitHub Action, process lineage graph | Planned |
| Phase 3 (Weeks 13–20) | YAML policy rules, shadow.run registry, VS Code extension, team dashboard | Planned |

**Immediate next steps:**
- Integrate eBPF network events into the risk scoring engine
- Re-enable `CLONE_NEWNET` and connect it to the eBPF observer for actual network blocking
- Call `parser.analyzeLog()` from `main.cpp` after sandbox completes
- Add `shadow diff` to compare behavior between two package versions

---

## Contributing

Rule and heuristic contributions are especially welcome.

```bash
git clone https://github.com/aadesh006/Shadow-Analyzer
cd Shadow-Analyzer
mkdir build && cd build
cmake .. && make
```

---

## Background

Shadow was built in response to the axios npm supply chain attack (March 2026). StepSecurity Harden-Runner — the only tool that caught the attack — is an enterprise-grade GitHub Actions product. There was no open-source, developer-local equivalent. Shadow fills that gap.

---
## Author

**Aadesh Chaudhari**  
GitHub: [@aadesh006](https://github.com/aadesh006)

*Built in response to the axios npm supply chain attack, March 2026*