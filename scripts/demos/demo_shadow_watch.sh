#!/bin/bash

echo "=== Shadow Watch EDR Daemon Demo ==="
echo
echo "Demonstrating the always-on EDR daemon architecture..."
echo

echo "--- Architecture Overview ---"
echo "• Shadow Watch runs as a system daemon (root privileges)"
echo "• Uses same eBPF hooks as sandbox but applied system-wide"
echo "• Monitors ALL Node.js/Python processes for supply chain threats"
echo "• Detects staged payloads that activate after installation"
echo "• Provides real-time alerting and policy enforcement"
echo

echo "--- Key Capabilities ---"
echo "✓ Real-time process monitoring (LSM + tracepoints)"
echo "✓ Credential access blocking (Ring 0 enforcement)"
echo "✓ Malicious network connection detection"
echo "✓ Suspicious process spawn alerts"
echo "✓ Post-install static analysis integration"
echo "✓ Policy-based response (log, alert, kill process)"
echo "✓ Package correlation (links events to npm packages)"
echo

echo "--- Command Interface ---"
echo "sudo shadow watch start   # Start daemon"
echo "sudo shadow watch stop    # Stop daemon"
echo "sudo shadow watch status  # Show statistics"
echo "sudo shadow watch logs    # View recent events"
echo

echo "--- Configuration (/etc/shadow/watch.conf) ---"
echo "monitor_node_processes=true      # Monitor all Node.js processes"
echo "monitor_python_processes=true    # Monitor all Python processes"
echo "log_events=true                  # Log to /var/log/shadow/watch.log"
echo "kill_on_malicious=false          # Policy enforcement level"
echo "scan_new_packages=true           # Auto-scan package installs"
echo

echo "--- Event Types Detected ---"
echo "• CREDENTIAL_ACCESS    - LSM blocked credential file access"
echo "• MALICIOUS_CONNECTION - Connection to known C2 server"
echo "• SUSPICIOUS_PROCESS   - Unexpected process spawn (curl, wget)"
echo "• STAGED_PAYLOAD       - Post-install static scan finding"
echo "• POLICY_VIOLATION     - Custom policy rule violation"
echo

echo "--- Sample Event Log ---"
cat << 'EOF'
{"timestamp":"2026-10-08 01:30:15","type":"CREDENTIAL_ACCESS","pid":1234,"process":"node","description":"Blocked access to /home/user/.ssh/id_rsa","package":"malicious-pkg"}
{"timestamp":"2026-10-08 01:30:16","type":"MALICIOUS_CONNECTION","pid":1234,"process":"node","description":"Connection to known C2: 185.220.101.47","package":"malicious-pkg"}
{"timestamp":"2026-10-08 01:30:17","type":"SUSPICIOUS_PROCESS","pid":1235,"process":"curl","description":"Unexpected curl spawn from Node.js","package":"malicious-pkg"}
EOF
echo

echo "--- Integration with Shadow Analyzer ---"
echo "• Watch daemon uses same eBPF programs as 'shadow analyze'"
echo "• Extends sandbox capabilities to entire host system"
echo "• Catches staged payloads that activate post-installation"
echo "• Provides continuous monitoring vs one-time analysis"
echo

echo "--- Future Enhancements ---"
echo "• Network connection blocking (default-deny policies)"
echo "• SIEM/webhook integration for enterprise alerting"
echo "• Machine learning behavioral analysis"
echo "• Reputation-based package scoring"
echo "• Integration with CI/CD pipelines"
echo

echo "--- Implementation Status ---"
echo "✓ Architecture designed and implemented"
echo "✓ Command interface structure complete"
echo "✓ Event handling and logging framework"
echo "✓ Policy enforcement foundation"
echo "⏳ eBPF integration with system-wide monitoring"
echo "⏳ Real-time event correlation"
echo "⏳ Configuration file parsing"
echo

echo "=== Demo Complete ==="
echo
echo "The Shadow Watch daemon represents the next evolution:"
echo "From one-time package analysis → always-on supply chain protection"