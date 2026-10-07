/**
 * shadow-test-malicious — preinstall.js
 *
 * Safe test payload that triggers every Shadow detection path.
 * ALL actions are sandboxed — nothing reaches the real filesystem or network.
 *
 * Detection paths exercised:
 *   [1] Credential file read  → LSM BLOCKED (shadow_rules.conf)
 *   [2] AWS credentials read  → LSM BLOCKED
 *   [3] SSH key read          → LSM BLOCKED
 *   [4] Outbound C2 connect   → connect() to known C2 IP (blocked by lsm/socket_connect)
 *   [5] Suspicious spawn      → spawns curl (blocked, triggers ALERT)
 *   [6] Outbound tunnel       → connect() to ngrok-style address
 *   [7] .env file read        → LSM BLOCKED
 */

const fs   = require('fs');
const net  = require('net');
const { execSync, spawnSync } = require('child_process');

console.log('[shadow-test] Starting malicious payload simulation...');

// ─── [1] Attempt to read /etc/passwd ────────────────────────────────────────
// Shadow LSM hook should block this with EPERM before the file opens.
console.log('[shadow-test] [1] Attempting to read /etc/passwd...');
try {
  fs.readFileSync('/etc/passwd', 'utf8');
  console.log('[shadow-test] WARNING: /etc/passwd was readable — LSM hook may not be active');
} catch (e) {
  console.log('[shadow-test] /etc/passwd blocked: ' + e.code);
}

// ─── [2] Attempt to read ~/.aws/credentials ─────────────────────────────────
console.log('[shadow-test] [2] Attempting to read ~/.aws/credentials...');
try {
  const home = process.env.HOME || '/tmp';
  fs.readFileSync(home + '/.aws/credentials', 'utf8');
  console.log('[shadow-test] WARNING: AWS credentials were readable');
} catch (e) {
  console.log('[shadow-test] AWS credentials blocked: ' + e.code);
}

// ─── [3] Attempt to read ~/.ssh/id_rsa ──────────────────────────────────────
console.log('[shadow-test] [3] Attempting to read ~/.ssh/id_rsa...');
try {
  const home = process.env.HOME || '/tmp';
  fs.readFileSync(home + '/.ssh/id_rsa', 'utf8');
  console.log('[shadow-test] WARNING: SSH key was readable');
} catch (e) {
  console.log('[shadow-test] SSH key blocked: ' + e.code);
}

// ─── [4] Attempt TCP connection to known C2 IP ──────────────────────────────
// 185.220.101.47 is in shadow_ip_blocklist.conf — connection should be blocked
// at Ring 0 by the lsm/socket_connect hook.
console.log('[shadow-test] [4] Attempting TCP connect to known C2 IP (185.220.101.47:4444)...');
const c2 = new net.Socket();
c2.setTimeout(2000);
c2.connect(4444, '185.220.101.47', () => {
  console.log('[shadow-test] WARNING: C2 connection succeeded — ip_blocklist may not be active');
  c2.destroy();
});
c2.on('error', (e) => console.log('[shadow-test] C2 connect blocked/failed: ' + e.code));
c2.on('timeout', () => { c2.destroy(); });

// ─── [5] Spawn curl (suspicious downloader) ──────────────────────────────────
// Shadow's execve tracepoint will catch this and fire ALERT.
// We pass --version so curl exits immediately — no actual network call.
console.log('[shadow-test] [5] Spawning curl (suspicious process)...');
try {
  spawnSync('curl', ['--version'], { timeout: 3000 });
  console.log('[shadow-test] curl was spawned (Shadow should have flagged this)');
} catch (e) {
  console.log('[shadow-test] curl spawn error: ' + e.message);
}

// ─── [6] Attempt TCP connection to a tunnel/exfil address ───────────────────
// Not in the IP blocklist but should trigger [SUSPICIOUS] → reverse DNS →
// domain-based MALICIOUS if Shadow's DNS path is working.
console.log('[shadow-test] [6] Attempting connect to suspicious non-CDN IP (91.92.255.80:443)...');
const tunnel = new net.Socket();
tunnel.setTimeout(2000);
tunnel.connect(443, '91.92.255.80', () => {
  console.log('[shadow-test] WARNING: Tunnel connect succeeded');
  tunnel.destroy();
});
tunnel.on('error', (e) => console.log('[shadow-test] Tunnel connect blocked/failed: ' + e.code));
tunnel.on('timeout', () => { tunnel.destroy(); });

// ─── [7] Attempt to read .env ────────────────────────────────────────────────
console.log('[shadow-test] [7] Attempting to read .env...');
try {
  // Try both the sandbox home and common locations
  fs.readFileSync('/tmp/.env', 'utf8');
  console.log('[shadow-test] WARNING: .env was readable');
} catch (e) {
  console.log('[shadow-test] .env blocked or not found: ' + e.code);
}

console.log('[shadow-test] Payload simulation complete.');
