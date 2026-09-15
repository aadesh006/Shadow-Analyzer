# Shadow Analyzer Test Suite

This directory contains automated tests for Shadow's behavioral analysis engine.

## Test Structure

```
tests/
├── README.md                    # This file
├── run_tests.sh                 # Main test runner
├── benign/                      # Tests for legitimate packages (should return CLEAN)
│   ├── test_lodash.sh
│   ├── test_chalk.sh
│   └── test_express.sh
├── malicious/                   # Simulated malicious behavior tests
│   ├── test_credential_access.sh
│   ├── test_suspicious_spawn.sh
│   ├── test_c2_connection.sh
│   └── test_memfd_execution.sh
├── fixtures/                    # Test package fixtures
│   └── malicious-test-package/  # Safe test package that simulates malware
└── results/                     # Test output (gitignored)
```

## Running Tests

**Requirements:**
- Root privileges (Shadow requires root)
- Shadow binary compiled in `../build/shadow`
- Internet connection (for benign package tests)

**Run all tests:**
```bash
cd tests
sudo bash run_tests.sh
```

**Run specific test category:**
```bash
sudo bash run_tests.sh benign      # Only benign package tests
sudo bash run_tests.sh malicious   # Only malicious behavior tests
```

**Run individual test:**
```bash
cd tests/benign
sudo bash test_lodash.sh
```

## Test Categories

### Benign Package Tests
Tests that analyze known-good npm packages. These should:
- Return verdict: `CLEAN`
- Complete without timeout
- Show only CDN network connections
- Not trigger any LSM blocks

**Packages tested:**
- `lodash` - Pure utility library (no network, no scripts)
- `chalk` - Terminal colors (minimal postinstall)
- `express` - Web framework (CDN downloads only)

### Malicious Behavior Tests
Simulated attack scenarios using controlled test packages. These should:
- Return verdict: `MALICIOUS`
- Trigger specific detection rules
- Block threats at kernel level

**Scenarios tested:**
1. **Credential Access** - Attempts to read `/etc/shadow`, `~/.ssh/id_rsa`
2. **Suspicious Process Spawn** - Spawns `curl`, `wget`, `python` during install
3. **C2 Connection** - Connects to known malicious IPs
4. **Memfd Execution** - Attempts fileless execution via `memfd_create`

## Test Output

Each test produces:
- Console output with color-coded results
- Exit code (0 = pass, 1 = fail)
- Detailed logs in `results/<test_name>.log`

## CI/CD Integration

To run tests in GitHub Actions:
```yaml
- name: Run Shadow Tests
  run: |
    cd tests
    sudo bash run_tests.sh
```

## Adding New Tests

1. Create test script in appropriate directory (`benign/` or `malicious/`)
2. Follow naming convention: `test_<name>.sh`
3. Use helper functions from `run_tests.sh`
4. Document expected behavior in comments
5. Update this README

## Limitations

- **Root required** - Tests must run as root (eBPF + namespaces)
- **Linux only** - Shadow is Linux-specific (kernel 5.8+)
- **Network dependent** - Benign tests require internet access
- **Timing sensitive** - Some tests may be affected by system load

## Troubleshooting

**Test hangs or times out:**
- Shadow has a 60-second sandbox timeout
- Check system load and available memory
- Verify internet connectivity for npm registry

**False positives:**
- Check if other processes are triggering LSM hooks
- Verify PID namespace filtering is working
- Review Shadow output for host system noise

**Tests fail to run:**
- Ensure Shadow binary exists: `ls -la ../build/shadow`
- Check kernel version: `uname -r` (must be 5.8+)
- Verify BPF LSM is active: `cat /sys/kernel/security/lsm | grep bpf`
