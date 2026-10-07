# Shadow Test Packages

Safe local packages for testing Shadow's detection pipeline end to end.

## Setup (after cloning or after reboot)

```bash
cd test-packages
npm pack shadow-test-malicious/
npm pack shadow-test-clean/
```

## Running

```bash
cd build

# Should produce MALICIOUS — triggers LSM blocks, curl spawn, C2 connections
sudo ./shadow analyze ../test-packages/shadow-test-malicious-1.0.0.tgz

# Should produce CLEAN — CDN traffic only, no threats
sudo ./shadow analyze ../test-packages/shadow-test-clean-1.0.0.tgz
```

## What shadow-test-malicious triggers

| Step | Action | Expected output |
|---|---|---|
| 1 | Read `/etc/passwd` | `LSM THREAT BLOCKED AT RING 0` |
| 2 | Read `~/.aws/credentials` | `LSM THREAT BLOCKED AT RING 0` |
| 3 | Read `~/.ssh/id_rsa` | `LSM THREAT BLOCKED AT RING 0` |
| 4 | Connect to `185.220.101.47:4444` | `CONNECTION BLOCKED AT RING 0` |
| 5 | Spawn `curl` | `[ALERT] Suspicious process spawned` |
| 6 | Connect to `91.92.255.80:443` | `CONNECTION BLOCKED AT RING 0` |

**Expected verdict: `MALICIOUS`**

## What shadow-test-clean triggers

- Writes two files to `/tmp`
- Connects to `104.16.0.1` (Cloudflare/npm CDN — trusted)
- Reads nothing sensitive, spawns nothing unexpected

**Expected verdict: `CLEAN`**

## Notes

- `.tgz` tarballs are excluded from git (`.gitignore`) — regenerate with `npm pack`
- Shadow copies tarballs to `/tmp` automatically — no manual copy needed
