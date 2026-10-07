/**
 * shadow-test-clean — preinstall.js
 *
 * Simulates a legitimate package postinstall:
 *   - Writes files to /tmp (the sandbox writable area)
 *   - Makes a TCP connection to the npm registry (trusted CDN)
 *   - Spawns only node (expected process)
 *   - Reads nothing sensitive
 *
 * Expected Shadow verdict: CLEAN
 * Expected Shadow diff output: a few files written to /tmp
 */

const fs  = require('fs');
const net = require('net');

console.log('[shadow-test-clean] Running legitimate postinstall simulation...');

// Write some files — visible in shadow diff output
fs.writeFileSync('/tmp/shadow-test-output.txt', 'build artifact from postinstall\n');
fs.mkdirSync('/tmp/shadow-test-cache', { recursive: true });
fs.writeFileSync('/tmp/shadow-test-cache/index.json', JSON.stringify({ built: true, ts: Date.now() }));
console.log('[shadow-test-clean] Wrote build artifacts to /tmp');

// Read a non-sensitive file — should not trigger any alert
try {
  fs.readFileSync('/tmp/package.json', 'utf8');
  console.log('[shadow-test-clean] Read package.json (non-sensitive, expected)');
} catch (e) { /* not present in all sandbox states */ }

// Connect to npm registry (trusted CDN — should appear as [NET], not [SUSPICIOUS])
console.log('[shadow-test-clean] Connecting to npm registry (should be [NET] trusted)...');
const sock = new net.Socket();
sock.setTimeout(3000);
sock.connect(443, '104.16.0.1', () => {
  console.log('[shadow-test-clean] npm registry reachable (trusted CDN)');
  sock.destroy();
});
sock.on('error', (e) => console.log('[shadow-test-clean] Registry connect: ' + e.code));
sock.on('timeout', () => sock.destroy());

console.log('[shadow-test-clean] Postinstall complete.');
