# Contributing to Shadow

Shadow is an early-stage open-source security tool built by a single developer. Any contribution — no matter how small — genuinely moves the project forward. This document explains how to get involved.

---

## Security Policy

## Reporting a Vulnerability

Shadow is an early-stage security tool. If you find a 
security vulnerability — especially one that allows 
sandbox escape or LSM hook bypass — please report it 
responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Email: aadeshchaudhari14@gmail.com
Or open a GitHub Security Advisory (private disclosure).

Include:
- Description of the vulnerability
- Steps to reproduce
- Your kernel version and distro
- Potential impact

I'll respond within 48 hours and work with you on 
a fix before public disclosure.

---

## Getting Started

### Set up the project

```bash
# Clone the repository
git clone https://github.com/aadesh006/Shadow-Analyzer
cd Shadow-Analyzer

# Install dependencies (Ubuntu / Debian)
sudo apt install clang bpftool libbpf-dev libelf-dev cmake build-essential

# Build
mkdir build && cd build
cmake ..
make

# Verify it works
sudo ./shadow analyze lodash      # should return CLEAN
sudo ./shadow analyze esbuild     # should return CLEAN with CDN traffic
```

### Check compatibility first

Shadow requires Linux kernel 5.8+ with eBPF LSM support. Run this before anything else:

```bash
echo "Kernel: $(uname -r)" && \
echo "BTF: $(ls /sys/kernel/btf/vmlinux 2>/dev/null && echo OK || echo MISSING)" && \
echo "BPF_LSM: $(cat /boot/config-$(uname -r) 2>/dev/null | grep CONFIG_BPF_LSM || echo NOT FOUND)" && \
echo "LSM list: $(cat /sys/kernel/security/lsm 2>/dev/null || echo NOT FOUND)"
```

All four lines must look healthy. If `bpf` is missing from the LSM list, see the README compatibility section for how to add it.

---

## Ways to Contribute

### Report a bug

If something doesn't work, open a GitHub issue with the `bug` label. A useful bug report includes:

- Your Linux distro and kernel version (`uname -r`)
- The full Shadow terminal output — copy everything
- The package you were analyzing
- What you expected to happen vs. what actually happened

### Report a false positive

If Shadow returns `MALICIOUS` on a package you believe is clean, open an issue with the `false-positive` label. Include the package name, version, and full output. These are high priority — false positives make the tool unusable.

### Expand the threat rules

`shadow_rules.conf` is the list of sensitive filenames the eBPF LSM hook blocks. It currently has 6 entries. Adding more sensitive file paths — SSH keys, cloud credentials, wallet files, CI/CD secrets — is one of the most useful contributions and requires no kernel knowledge whatsoever.

The format is one filename per line. Comments start with `#`.

```
# Example additions
id_ecdsa
id_dsa
.gcloud
wallet.dat
netrc
```

### Expand the threat intelligence

`core/src/threat_intel.cpp` contains two functions that classify network connections:

- `is_malicious()` — known C2 domains and IPs that should trigger an alert
- `is_trusted_cdn()` — known-good CDN destinations that should never be flagged

Both benefit from more entries. Sources like [URLhaus](https://urlhaus.abuse.ch/) and [MalwareBazaar](https://bazaar.abuse.ch/) document known malware infrastructure. CDN IP ranges are published by Cloudflare, Fastly, and npm.

### Test on different distros

Shadow has only been actively tested on Ubuntu 24.04. Testing on other supported distros — Fedora, Arch, Kali, Debian 12 — and reporting your results (even if everything works) helps build the compatibility picture.

### Improve documentation

If something in the README or this file is unclear, a PR fixing it is a real contribution. Good documentation is what makes the difference between a project people try once and a project people actually use.

### Review the code

If you have experience in kernel security, eBPF, or Linux systems programming, a code review is the most valuable thing you can contribute. Shadow is built by someone still learning this space and there are almost certainly things that need to be done better. A pointed comment on a PR, a question in an issue, or a review of a specific file is all useful.

---

## Submitting a Pull Request

1. Fork the repository
2. Create a branch with a descriptive name:
   ```bash
   git checkout -b feat/expand-shadow-rules
   git checkout -b fix/false-positive-pkexec
   ```
3. Make your changes
4. Test that `lodash` and `esbuild` still return the correct verdicts
5. Open a PR with a clear description of what changed and why

**PR description should include:**
- What the change does
- What problem it solves or what it improves
- How you tested it
- Your kernel version and distro

---

## Starting a Conversation

Not ready to open a PR but have a question, an idea, or want to understand the design before diving in? Open a GitHub issue with the `question` or `discussion` label. There are no stupid questions — if something is unclear, it means the documentation needs to be better.

You can also reach out directly via GitHub.

---

## Good First Issues

Look for issues tagged `good first issue` in the GitHub issue tracker. These are tasks that don't require deep familiarity with the codebase and are a good way to get oriented before tackling something larger.

---

*Shadow is early-stage. Every contribution counts.*
