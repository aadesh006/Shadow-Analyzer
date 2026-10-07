# Shadow Analyzer — Development Progress

> This file tracks all changes, improvements, and work-in-progress items across sessions.
> Network namespace isolation (`CLONE_NEWNET`) is deferred — see Deferred section.

---

## Project Snapshot (as of 2026-09-15)

### Current Component Status

| Component | Status | Notes |
|---|---|---|
| Linux namespace sandbox (PID, MNT, UTS, IPC, USER) | ✅ Working | `clone()` with namespace flags |
| `pivot_root` filesystem jail | ✅ Working | Host FS fully severed in child |
| Identity downgrade (sandbox root → host nobody) | ✅ Working | SUDO_UID/GID mapping |
| eBPF execve tracepoint — process tree tracking | ✅ Working | PID-ns scoped via `is_in_sandbox()` |
| eBPF connect tracepoint — network connection capture | ✅ Working | IPv4 + IPv6 classified separately |
| eBPF LSM `file_open` hook — credential file blocking | ✅ Working | Sensitive parent-dir check + blocklist |
| Dynamic blocklist via eBPF Hash Map | ✅ Working | Loaded from `shadow_rules.conf` |
| IP blocklist via eBPF Hash Map | ✅ Working | Loaded from `shadow_ip_blocklist.conf` |
| CDN allowlist (Cloudflare, npm, GitHub CDN) | ✅ Working | In `threat_intel.cpp` |
| Known C2 domain/IP blocklist | ✅ Working | Partial — needs expansion |
| Suspicious process spawn detection (curl, wget, python) | ✅ Working | observer.cpp event type 3 |
| `memfd_create` detection (fileless execution) | ✅ Working | Event type 4 |
| Sandbox execution timeout (60s) | ✅ Working | SIGKILL + exit code 124 |
| Unified MALICIOUS / CLEAN / TIMEOUT verdict | ✅ Working | main.cpp verdict block |
| PID-scoped LSM filtering (sandbox-only events) | ✅ Working | Dual filter: namespace inum + ancestor PID walk — catches nested unshare() |
| OverlayFS filesystem delta (`shadow diff`) | ✅ Working | Tracks all files written/modified/deleted by the package |
| `shadow watch` — continuous host EDR daemon | ⏳ Planned | — |
| `shadow policy sync` — remote threat feed | ⏳ Planned | — |
| pip / PyPI support | ⏳ Planned | — |
| GitHub Actions integration | ⏳ Planned | — |

---

## Known Issues & Gaps (pre-session baseline)

1. **LSM false positives** — The `is_in_sandbox()` check uses PID namespace inode to filter events. However, during the brief window between `clone()` returning and `register_sandbox_pid()` being called, the sandbox_ns map entry is 0, so the helper returns 0 (fail-closed). This means LSM events in that window are silently dropped, not falsely flagged. The real false-positive risk is the opposite: host processes that happen to share the same PID ns inum (shouldn't happen — ns inums are unique) or processes the filter erroneously misses.

2. **`shadow_ip_blocklist.conf` contains test IPs** — `1.1.1.1` (Cloudflare DNS) and `104.16.1.34` (a Cloudflare CDN IP) are in the malicious blocklist. These are not malicious. This will cause false positive MALICIOUS verdicts on legitimate packages that hit Cloudflare CDN.

3. **`threat_intel.cpp` CDN allowlist is shallow** — Only covers a small subset of Cloudflare IP ranges (`104.16.x` through `104.21.x`, `172.66.x`, `172.67.x`). Cloudflare operates a much wider range. npm's registry and CDN span a broader set of addresses.

4. **`threat_intel.cpp::is_malicious()` only checks domains, not IPs** — The function receives a raw IP string (from `inet_ntoa`) but the static list contains hostnames. IP-to-hostname matching never fires unless the input happens to contain a substring match against a domain string, which it won't for a bare IP like `185.220.101.47`.

5. **No DNS resolution in the event path** — `resolve_ipv4()` exists in `ThreatIntel` but is never called in `observer.cpp`. All IPs are compared as raw strings. Domain-based C2 detection in `is_malicious()` is effectively dead code for network events.

6. **`sandbox.cpp::construct_prison()` passes `args->argv[2]` as target path** — This hardcodes the tarball path as the third CLI argument. If the user runs `shadow analyze lodash` (no version/path), `argv[2]` is the package name string, not a path, and the copy logic silently fails (access check on a non-path string). Harmless but fragile.

7. **Host process noise filter in `observer.cpp` is hardcoded** — Filters `systemd-resolve`, `chrome`, `code`, etc. by comm name. `comm` is only 16 bytes and can be spoofed by a malicious process.

---

## Session Work Log

### Session 1 — 2026-09-15

**Goal:** Establish progress tracking, review build state, and complete targeted improvements across threat intel, PID-scoped filtering, and filesystem diff.

#### ✅ Task 1 — Created PROGRESS.md (this file)

#### ✅ Task 2 — Build state review
- Build is clean: `cmake .. && make` produces the `shadow` binary with zero errors or warnings.
- Identified 6 bugs in the baseline (see Known Issues section above).

#### ✅ Task 3 — PID-scoped LSM filtering improvements (`shadow.bpf.c`, `observer.cpp`)

**Problem:** `is_in_sandbox()` relied solely on the PID namespace inode number. A malicious package that calls `unshare(CLONE_NEWPID)` would create a nested PID namespace with a different inum and escape the filter entirely.

**Fix — dual filter in `is_in_sandbox()`:**
- Added a new `sandbox_root_pid` BPF map (ARRAY, 1 entry) storing the host-side PID of the sandbox root process.
- Added `is_descendant_of_sandbox()` — walks the task's `real_parent` chain up to 16 levels (bounded for BPF verifier), returns 1 if the sandbox root PID is found in the ancestry.
- `is_in_sandbox()` now returns 1 if **either** check passes: namespace inum match **OR** ancestor PID walk match. Both checks short-circuit — if the namespace check passes the walk is skipped entirely.
- Updated `Observer::register_sandbox_pid()` to populate both `sandbox_ns` (inum) and `sandbox_root_pid` (host PID) maps on the same `clone()` callback.

**Also fixed:** duplicate `10.x.x.x` private range filter in `handle_connect` — was checked twice with a redundant dead block between them. Cleaned up and added a comment block for all three RFC-1918 ranges.

#### ✅ Task 4 — OverlayFS filesystem delta (`shadow diff`) (`sandbox.cpp`, `sandbox.h`, `main.cpp`)

**What was built:**

The sandbox's `/tmp` is now backed by an OverlayFS mount instead of a plain `tmpfs`. Every file the package creates or modifies during install lands in the OverlayFS `upper` layer on the host. Deletions appear as whiteout files (`.wh.<name>`). After the sandbox exits, `main.cpp` walks the upper dir and prints the full filesystem delta before the verdict.

**Implementation details:**

- `setup_overlay_dirs()` in `sandbox.cpp` — creates `/tmp/shadow_overlay/{lower,upper,work,merge}` on the host before `clone()`. Mounts OverlayFS at `merge` with `lower` as the empty read-only base.
- `construct_prison()` — binds `merge` to `/tmp` inside the jail instead of mounting a plain `tmpfs`. Falls back to plain `tmpfs` gracefully if OverlayFS mount failed.
- `sandbox.h` — added `overlay_upper_dir` public field, populated by `run()` after successful overlay setup.
- `main.cpp::print_diff()` — recursive directory walker over the upper dir. Labels new/modified files with `[+]`, deleted files (whiteouts) with `[-] DELETED`. Shows file sizes. Runs after `kernel_observer.stop()` but before the final verdict block.

**Example output:**
```
[Shadow] ══════════════ FILESYSTEM DELTA ══════════════
[DIFF] Files written or modified by the package:
  [+] /node_modules/axios/package.json (4KB)
  [+] /node_modules/axios/lib/axios.js (12KB)
  [+] /.npm/_cacache/... (various)
  [-] DELETED  /tmp/somefile

  47 file(s) written/modified, 1 file(s) deleted.
```

#### ✅ Task 5 — Threat intel improvements (`threat_intel.cpp`, `shadow_ip_blocklist.conf`, `shadow_rules.conf`, `observer.cpp`)

**`threat_intel.cpp` — CDN allowlist expanded:**
- Was: 8 Cloudflare IP prefixes (`104.16–104.21.x`, `172.66–67.x`)
- Now: Full Cloudflare `104.16.0.0/12` (104.16–104.31.x), full `172.64.0.0/13` (172.64–172.71.x), plus `162.158.x`, `188.114.x`, `190.93.x`, `197.234.240.x`, `198.41.128–143.x`
- Added Fastly CDN (`151.101.x.x`), GitHub API/CDN (`140.82.x`, `185.199.x`, `192.30.252–255.x`)
- Added domain entries: `ghcr.io`, `fastly.com`, `cloudfront.net`, `s3.amazonaws.com`

**`threat_intel.cpp` — `is_malicious()` dead code fixed:**
- Was: only checked domain names, but `observer.cpp` passed raw IP strings — domain list never fired on network events.
- Now: checks both domain substrings AND exact raw IP matches in the same function. The parameter renamed from `hostname` to `ip_or_host` to reflect this.
- Added tunnel/exfil services: `ngrok-free.app`, `serveo.net`, `pagekite.me`, `playit.gg`, `bore.pub`, `telebit.io`
- Added webhook/capture services: `webhook.site`, `pipedream.net`, `oastify.com` (new Burp Collaborator domain), `webhook.run`
- Added confirmed C2 raw IPs: `185.220.101.47/34/35/36/48` (Tor C2 relays seen in npm attacks), `45.142.212.100`, `91.92.255.80`, `194.165.16.29`

**`observer.cpp` — reverse DNS wired into event path:**
- Was: `resolve_ipv4()` existed but was never called; domain-based C2 detection was dead for all network events.
- Now: for IPs that are neither known-malicious nor known-CDN after the raw IP check, `resolve_ipv4()` is called once to get the hostname. Classification is then re-run against the hostname. Display string shows both (`hostname (raw_ip)`).

**`shadow_ip_blocklist.conf` — false positives removed:**
- Was: contained `1.1.1.1` (Cloudflare DNS) and `104.16.1.34` (Cloudflare CDN) — both legitimate IPs that would have caused false MALICIOUS verdicts on any package touching Cloudflare.
- Now: replaced with confirmed C2 IPs from axios and TanStack attacks with source comments.

**`shadow_rules.conf` — expanded:**
- Was: 6 entries (`passwd`, `shadow`, `credentials`, `id_rsa`, `id_ed25519`, `.env`)
- Now: 30+ entries covering SSH config/keys/authorized_keys, AWS credentials, GnuPG keyring files, `.netrc`, `.npmrc`, `.pypirc`, `.gitconfig`, additional env file variants

---

## Deferred Items

### Network Namespace Isolation (`CLONE_NEWNET`)

Intentionally deferred. Adding `CLONE_NEWNET` to the `clone()` flags severs the sandbox from the host network entirely, which would prevent npm from reaching the registry and CDN at all. Making this useful requires:

- A bridge/veth pair setup to give the sandbox a controlled outbound path
- Or a transparent proxy inside the namespace that captures and logs connections

Neither is trivial. The current approach (observe-and-classify without blocking) gives useful signal while keeping the sandbox functional. `CLONE_NEWNET` is a Phase 2 item per the original roadmap.

---

## Upcoming Work (next session)

- [ ] Network namespace isolation (`CLONE_NEWNET`) — Phase 2 per roadmap, currently deferred
- [ ] `shadow watch` — continuous EDR daemon design
- [ ] pip/PyPI package manager support
- [ ] CO-RE portability for RHEL/Amazon Linux

### Session 2 — 2026-09-15

**Goal:** Build a test suite for everything that can run without root or eBPF.

#### ✅ Test suite — 43 test cases, 313 assertions, all passing

**Framework:** Catch2 v3.5.3 (amalgamated single-header, no install required — bundled at `tests/catch2/`).

**Test files:**

| File | Suite tag | What it tests |
|---|---|---|
| `tests/test_threat_intel.cpp` | `[threat_intel]` | `is_trusted_cdn()` and `is_malicious()` — all IP ranges, all domain entries, false-positive regression |
| `tests/test_rules_parser.cpp` | `[rules]` | `shadow_rules.conf` and `shadow_ip_blocklist.conf` — file presence, required entries, no false-positive CDN IPs, valid IPv4 format, no duplicates |
| `tests/test_observer_logic.cpp` | `[observer]` | Host noise filter, expected/unexpected process detection, downloader detection, combined ALERT logic |
| `tests/test_diff_walker.cpp` | `[diff]` | OverlayFS upper-dir walker — empty dir, missing dir, single file, nested dirs, whiteout (deletion) detection, mixed write+delete |

**Bug caught by tests:**
- `is_malicious("notngrok.io")` returned `true` — substring `"ngrok.io"` matched inside `"notngrok.io"`. Fixed by switching from `find()` substring to exact + `.`-boundary suffix matching. The test suite caught this immediately.

**How to run:**
```bash
cd build
./shadow_tests                    # run all
./shadow_tests [threat_intel]     # threat intel only
./shadow_tests [rules]            # conf file validation only
./shadow_tests [observer]         # observer logic only
./shadow_tests [diff]             # diff walker only
make test                         # via ctest
```

### Session 3 — 2026-09-16

**Fixes and cleanup after live testing.**

#### ✅ OverlayFS stale state — "up to date" bug fixed
- Root cause: `setup_overlay_dirs()` only unmounted the merge point but left `upper` and `work` intact. npm saw the previous run's `sandbox_pkg/` still installed and skipped the install, so `preinstall` never fired.
- Fix: wipe all contents of `upper` and `work` before remounting on every run.

#### ✅ Filesystem delta — stopped flooding terminal
- `print_diff()` replaced with `write_diff_log()` — full file list written to `/tmp/shadow_diff_<pid>.log`.
- Terminal now shows one summary line only.

#### ✅ Tarball staging — works from any path now
- Previously only tarballs already in `/tmp` staged correctly. Passing `/home/aadesh/...` caused `ERROR: Failed to stage`.
- Fix: `Sandbox::run()` copies any tarball outside `/tmp` to `/tmp` on the host side before `clone()`. Any absolute path works directly.

#### ✅ Dedicated install subdir + fresh cache per run
- npm now runs from `/tmp/sandbox_pkg/` instead of `/tmp/` directly.
- Unique per-run cache dir `--cache=/tmp/.npm-<pid>` + `--force` ensures full install every time.

#### ✅ Live test results confirmed
- `shadow-test-malicious-1.0.0.tgz` → **MALICIOUS** ✅ (LSM blocks, curl alert, C2 connections blocked at Ring 0)
- `express` (real registry package) → **CLEAN** ✅ (CDN traffic only)

#### ✅ .gitignore + git tracking cleanup
- `tests/` and `test-packages/` excluded and removed from git tracking (`git rm -r --cached tests/`)

### Session 3 — 2026-09-16

**Goal:** Add apt/deb package support (Approach 1 — sandbox maintainer scripts only).

#### ✅ apt/deb support implemented

**How it works:**
1. `shadow apt <package>` — runs `apt-get download` to fetch the `.deb` without installing
2. `shadow apt <path/to/pkg.deb>` — accepts a local `.deb` directly
3. `AptAnalyzer::extract_scripts()` runs `dpkg-deb --control` to extract the `DEBIAN/` directory
4. Each maintainer script (`preinst`, `postinst`, `prerm`, `postrm`) is staged into `/tmp` and run inside Shadow's existing sandbox via `sh <script> configure`
5. The same eBPF hooks fire — LSM credential blocking, network tracing, process spawn detection
6. The real `apt install` never runs — only the scripts are sandboxed

**New files:**
- `core/include/apt_analyzer.h` — AptAnalyzer class declaration
- `core/src/apt_analyzer.cpp` — fetch + extract_scripts() implementation
- `test-packages/shadow-test-malicious_1.0.0_all.deb` — test .deb with malicious postinst

**Usage:**
```bash
# Analyze a package from apt registry
sudo ./shadow apt curl

# Analyze a local .deb
sudo ./shadow apt /home/aadesh/Desktop/Shadow/test-packages/shadow-test-malicious_1.0.0_all.deb
```
