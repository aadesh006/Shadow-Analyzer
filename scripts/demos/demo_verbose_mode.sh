#!/bin/bash

echo "=== Shadow Analyzer - Verbose vs Quiet Mode Demo ==="
echo
echo "Shadow now supports clean output by default with optional verbose logging!"
echo

echo "--- DEFAULT MODE (Clean Output) ---"
echo "Command: shadow analyze lodash"
echo "Sample Output:"
cat << 'EOF'
=== Shadow Analyzer v1.0 ===

[RESULT] CLEAN — No threats detected.
EOF
echo

echo "--- VERBOSE MODE (Detailed Logs) ---"  
echo "Command: shadow analyze lodash --verbose"
echo "Sample Output:"
cat << 'EOF'
=== Shadow Analyzer v1.0 ===
[Shadow] Target: lodash

[Shadow] Loading dynamic threat intelligence...
[Shadow] Rules loaded from: ../shadow_rules.conf
  [RULE] LSM block active: passwd
  [RULE] LSM block active: shadow
  [... 25 more rules ...]
[Shadow] 27 rules injected into Ring 0 kernel map.
[Shadow] 8 known-malicious IPs loaded into Ring 0 block map.
[eBPF] Kernel probe attached. All hooks live.
[Shadow] Launching npm inside sandbox...
[Shadow] Spawning isolated namespaces
[Shadow] Sandbox created. Host mapped PID: 12345
[eBPF] Sandbox PID namespace registered: inum=4026532570
[eBPF] Sandbox root PID registered: host_pid=12345
[NET] Setting up network namespace isolation...
[NET] Network namespace active. Sandbox: 10.88.0.2 → Host: 10.88.0.1 → internet
  [Prison] OverlayFS /tmp mounted — filesystem diff active.
  [Prison] Host filesystem amputated successfully.
  [Prison] Sandbox context created.
  [Prison] Sandbox identity downgraded to UID: 1000

npm WARN using --force Recommended protections disabled.
  [NET] PID: 12345 -> 104.16.10.34 Port: 443
  [NET] PID: 12345 -> 104.16.10.34 Port: 443
  [... network connections ...]

added 27 packages in 3s
[Shadow] Sweeping ring buffer for final events...
[eBPF] Kernel hooks detached.
[DIFF] 518 file(s) written, 0 deleted. Full log: /tmp/shadow_diff_12345.log
[STATIC] Post-install static scan temporarily disabled (fixing segfault)

[RESULT] CLEAN — No threats detected.
EOF
echo

echo "--- KEY IMPROVEMENTS ---"
echo "✅ Clean default output - no log spam"
echo "✅ --verbose flag for detailed debugging"
echo "✅ Suspicious findings always shown (even in quiet mode)"
echo "✅ Better user experience for CI/CD integration"
echo

echo "--- Usage Examples ---"
echo "# Clean output for scripts/CI"
echo "shadow analyze axios"
echo 
echo "# Detailed output for debugging" 
echo "shadow analyze axios --verbose"
echo
echo "# Works with all package managers"
echo "shadow pip requests --verbose"
echo "shadow apt curl --verbose"
echo

echo "=== User Experience Dramatically Improved! ==="