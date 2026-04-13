# Shadow
### Dependency Runtime Behavior Analyzer

> **Every static analysis tool missed the axios attack. Shadow would have caught it in 2 seconds.**

Shadow is an open-source runtime behavioral sandbox for npm and pip packages. Where existing tools (npm audit, Snyk, Dependabot) rely on static CVE databases, Shadow actually runs the package in an isolated Linux namespace, hooks into the kernel with eBPF, and watches every syscall, network connection, file access, and environment variable read it makes — before your system is touched.

```bash
$ shadow analyze axios@1.14.1

[T+0.3s]  HIGH     Process spawn from postinstall hook → node setup.js
[T+1.2s]  CRITICAL Outbound network call during install → sfrclak.com:8000
[T+1.4s]  HIGH     Sensitive env var read → AWS_ACCESS_KEY_ID
[T+1.5s]  MEDIUM   /proc read → /proc/self/environ

Risk: CRITICAL — Install blocked.
```

---

## Why Shadow Exists

On **March 31, 2026**, North Korean threat actor UNC1069 compromised the npm account of the primary axios maintainer and published two malicious versions (`axios@1.14.1`, `axios@0.30.4`) with a RAT dropper injected as a transitive dependency. The malware called home to a C2 server within 2 seconds of `npm install`, harvested credentials and environment variables, then deleted itself — leaving no trace.

**npm audit reported nothing. Snyk reported nothing. The malicious versions were live for 2 hours 54 minutes.**

Shadow catches this class of attack by observing what a package *actually does at runtime*, not what its source code claims to do.

| Tool | Approach | Catches axios attack? |
|---|---|---|
| npm audit | CVE database lookup | ❌ No CVE existed |
| Snyk / Dependabot | Static dependency graph | ❌ Source code was unchanged |
| GitHub secret scanning | Regex on source files | ❌ Payload was obfuscated |
| SLSA / provenance | Build attestation | ❌ Token theft bypasses it |
| **Shadow** | **Runtime syscall observation** | **✅ C2 call flagged in 2 seconds** |

---

## Installation

```bash
# Debian / Ubuntu
apt install shadow-analyzer

# macOS
brew install shadow-analyzer

# npm (cross-platform)
npm i -g shadow-analyzer
```

**Requirements:** Linux kernel 5.8+ with BTF enabled (Ubuntu 20.04+, Debian 11+). macOS support via DTrace (experimental).

---

## Usage

### Analyze a package
```bash
shadow analyze <package>@<version>

shadow analyze axios@1.14.1
shadow analyze requests@2.31.0
```

### Diff two versions
```bash
shadow diff <package>@<v1> <package>@<v2>

$ shadow diff axios@1.14.0 axios@1.14.1

+ NEW  network_connect  sfrclak.com:8000       [CRITICAL]
+ NEW  exec             node setup.js          [HIGH]
+ NEW  env_read         AWS_ACCESS_KEY_ID      [HIGH]
+ NEW  file_open        /proc/self/environ     [MEDIUM]

Risk delta: CLEAN → CRITICAL
Recommendation: DO NOT UPGRADE
```

### Watch mode (real-time monitoring)
```bash
shadow watch
# Monitors all installs in current project in real time
```

### Scan entire project
```bash
shadow scan
# Analyzes all dependencies from package-lock.json / poetry.lock
```

---

## Risk Levels

| Level | Trigger | Action |
|---|---|---|
| **CRITICAL** | C2 network call, credential file access, AWS metadata IP | Block install, immediate alert |
| **HIGH** | Outbound network during install, shell spawn, env harvesting | Block in CI strict mode |
| **MEDIUM** | Unexpected file writes, /proc reads | Warn, require approval |
| **LOW** | Normal reads, writes to tmp | Log only |
| **CLEAN** | No suspicious behavior | Pass |

Risk is scored on the **worst single event** — one CRITICAL event makes the package CRITICAL regardless of everything else.

---

## How It Works

Shadow is built in four layers:

```
┌─────────────────────────────────────────────────────┐
│  User Interface Layer                               │
│  shadow CLI (Python) | GitHub Action | VS Code Ext  │
├─────────────────────────────────────────────────────┤
│  Analysis Engine Layer                              │
│  Risk Rule Engine | Behavior Classifier | Diff Eng  │
├─────────────────────────────────────────────────────┤
│  Observation Layer                                  │
│  eBPF Programs (C) | Syscall Parser | Net Monitor   │
├─────────────────────────────────────────────────────┤
│  Sandbox Layer                                      │
│  Linux Namespaces | tmpfs | seccomp | cgroup limits │
└─────────────────────────────────────────────────────┘
```

### Sandbox
Each analysis run creates a fresh Linux namespace with PID, NET, MNT, and USER isolation. The package sees a clean tmpfs filesystem — not your home directory or credentials. A cgroup limits CPU and memory so a malicious package cannot exhaust host resources during analysis.

### eBPF Observer
eBPF programs are loaded into the Linux kernel and attached to syscall entry/exit points before the sandboxed process starts. The package is born already being watched — with no way to detect or disable the observer. Shadow hooks:

| Syscall | What's captured |
|---|---|
| `openat` / `open` | Path, flags, PID, timestamp |
| `connect` / `sendto` | Destination IP, port, protocol |
| `execve` / `execveat` | Command, args, parent PID |
| `getenv` / environ | Variable name |
| `unlink` / `unlinkat` | Self-deletion patterns |
| `mount` / `unshare` | Namespace escape attempts |

### Why not Docker?
Docker adds a PID mapping problem, a ~50ms startup blind spot, and requires a daemon — while still needing the same kernel privileges Shadow requires anyway. Shadow spawns namespaces directly so the eBPF observer loads before the package process exists. See [docs/why-not-docker.md](docs/why-not-docker.md) for the full explanation.

### Risk Rule Engine
Rules are YAML-defined and community-extensible. Add custom rules in `.shadow/policy.yaml` in your repository:

```yaml
rules:
  - name: credential_file_access
    match: file_open path contains [".aws/credentials", ".ssh/id_rsa"]
    risk: CRITICAL
    message: Package attempted to read credential files

  - name: unexpected_outbound_install
    match: net_connect AND package_phase == install
    risk: HIGH
    message: Outbound network call during package install
```

---

## CI/CD Integration

### GitHub Actions
```yaml
- name: Shadow dependency scan
  uses: shadow-analyzer/action@v1
  with:
    fail_on: HIGH        # or CRITICAL for less strict mode
    token: ${{ secrets.GITHUB_TOKEN }}
```

Automatically scans on `package.json` / `requirements.txt` changes. Posts a risk report as a PR comment. Blocks merge on HIGH or CRITICAL findings.

### Policy as Code
Commit `.shadow/policy.yaml` to your repository for custom rules, org-wide risk thresholds, and package allowlisting. Works with `shadow scan` across monorepos.

---

## Project Status

> ⚠️ **Shadow is currently in active development.** Phase 1 (core engine) is in progress. The CLI and sandbox are functional. eBPF observer upgrade and full distribution packaging are in progress.

| Phase | Scope | Status |
|---|---|---|
| Phase 1 (Weeks 1–6) | Core engine, CLI, apt/brew/npm distribution | In progress |
| Phase 2 (Weeks 7–12) | GitHub Action, process lineage graph, container seccomp generator | Planned |
| Phase 3 (Weeks 13–20) | shadow.run registry, VS Code extension, team dashboard | Planned |

---

## Test Suite

Shadow is validated against 25+ known malicious packages including:

- `axios@1.14.1` — March 2026 supply chain attack, RAT dropper, C2 call
- `event-stream@3.3.6` — 2018 bitcoin theft via transitive dep
- `ua-parser-js@0.7.29` — 2021 cryptominer + credential stealer
- `plain-crypto-js@4.2.1` — decoy package used in axios attack
- `colors@1.4.0` — 2022 protestware infinite loop

---

## Technology Stack

| Component | Technology |
|---|---|
| Sandbox orchestrator | C++ |
| eBPF kernel programs | C (clang + BPF backend) |
| CLI | Python |
| Risk rule engine | C++ + YAML |
| GitHub Action | TypeScript |
| VS Code extension | TypeScript |
| Public registry (shadow.run) | FastAPI + PostgreSQL |
| Local cache | SQLite |
| eBPF loader | libbpf |
| macOS observation | DTrace |

---

## Known Limitations

- **Linux kernel 5.8+ required** for eBPF/BTF. Ubuntu 18.04 and earlier are not supported.
- **macOS support is experimental.** DTrace on macOS with SIP enabled has restricted cross-process visibility. Feature parity with Linux is not guaranteed.
- **Windows is not natively supported.** WSL2 works for local use but not for Windows-hosted CI runners.
- **Staged / time-delayed payloads** that behave cleanly during a short analysis window will not be caught by a single-pass analysis. Multi-pass analysis is on the roadmap.
- **Sandbox environment detection** by highly sophisticated malware (timing analysis, namespace ID inspection) is a known attack vector. Shadow's eBPF invisibility addresses the most common detection method (TracerPid) but is not a complete mitigation against nation-state-grade evasion.

---

## Contributing

Rule contributions are especially welcome. If you encounter a false positive or have a rule for a known malicious behavior pattern, open a PR against `rules/`.

```bash
git clone https://github.com/aadesh006/Shadow-Analyzer
cd Shadow-Analyzer
make dev       # builds core + CLI in dev mode
make test      # runs test suite against known malicious packages
```

---

## Background

Shadow was built in response to the axios npm supply chain attack (March 2026). StepSecurity Harden-Runner — the only tool that caught the attack — is an enterprise-grade GitHub Actions product requiring organizational sign-up and significant cost for private repositories. There was no open-source, developer-local equivalent. Shadow fills that gap.

---

*Shadow — shadow-analyzer.run | github.com/shadow-analyzer*
*Built in response to the axios npm supply chain attack, March 2026*