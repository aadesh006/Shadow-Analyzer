#!/bin/bash

echo "=== Enhanced Static Scanner Demo ==="
echo
echo "Testing advanced pattern detection for sophisticated obfuscation..."
echo

# Create a mock node_modules structure with the enhanced test package
TEST_DIR="/tmp/shadow_advanced_test_$$"
mkdir -p "$TEST_DIR/node_modules/shadow-test-advanced-threats"

# Copy our enhanced test package to the mock location
cp -r /home/aadesh/Desktop/Shadow/test-packages/shadow-test-advanced-threats/* "$TEST_DIR/node_modules/shadow-test-advanced-threats/"

echo "Enhanced test package deployed to: $TEST_DIR/node_modules/"
echo "Package contains advanced threats:"
echo "  • String concatenation obfuscation ('ev' + 'al')"
echo "  • Function constructor eval patterns"
echo "  • Hex and XOR encrypted payloads"
echo "  • Anti-debugging techniques"
echo "  • Environment fingerprinting"
echo

# Enhanced test program with detailed reporting
cat > /tmp/test_enhanced_scanner.cpp << 'EOF'
#include "/home/aadesh/Desktop/Shadow/core/include/static_scanner.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: test_enhanced_scanner <directory>" << std::endl;
        return 1;
    }
    
    StaticScanner scanner;
    StaticScanResult result = scanner.scan_node_modules(argv[1]);
    
    std::cout << "\n=== ENHANCED STATIC SCAN RESULTS ===" << std::endl;
    std::cout << "Files scanned: " << result.files_scanned << std::endl;
    std::cout << "Findings: " << (result.has_findings ? "YES" : "NO") << std::endl;
    std::cout << "Total patterns detected: " << result.findings.size() << std::endl;
    
    if (result.has_findings) {
        std::cout << "\n--- BASIC THREAT CATEGORIES ---" << std::endl;
        if (result.eval_patterns > 0) std::cout << "  • eval(base64) patterns: " << result.eval_patterns << std::endl;
        if (result.base64_payloads > 0) std::cout << "  • Large base64 payloads: " << result.base64_payloads << std::endl;
        if (result.obfuscated_code > 0) std::cout << "  • Obfuscated code: " << result.obfuscated_code << std::endl;
        if (result.suspicious_processes > 0) std::cout << "  • Suspicious processes: " << result.suspicious_processes << std::endl;
        if (result.credential_access > 0) std::cout << "  • Credential access: " << result.credential_access << std::endl;
        
        std::cout << "\n--- ADVANCED THREAT CATEGORIES ---" << std::endl;
        if (result.string_concat_obfuscation > 0) std::cout << "  • String concatenation obfuscation: " << result.string_concat_obfuscation << std::endl;
        if (result.function_constructor_usage > 0) std::cout << "  • Function constructor usage: " << result.function_constructor_usage << std::endl;
        if (result.encrypted_payloads > 0) std::cout << "  • Encrypted payloads: " << result.encrypted_payloads << std::endl;
        if (result.anti_analysis > 0) std::cout << "  • Anti-analysis techniques: " << result.anti_analysis << std::endl;
        if (result.environment_checks > 0) std::cout << "  • Environment fingerprinting: " << result.environment_checks << std::endl;
        
        std::cout << "\n--- DETAILED FINDINGS ---" << std::endl;
        for (const auto& finding : result.findings) {
            std::cout << "  • " << finding << std::endl;
        }
    }
    
    std::cout << "\n--- THREAT ASSESSMENT ---" << std::endl;
    int total_patterns = result.eval_patterns + result.base64_payloads + result.obfuscated_code +
                        result.suspicious_processes + result.credential_access + result.string_concat_obfuscation +
                        result.function_constructor_usage + result.encrypted_payloads + 
                        result.anti_analysis + result.environment_checks;
    
    if (total_patterns >= 5) {
        std::cout << "  VERDICT: HIGHLY SUSPICIOUS - Multiple advanced obfuscation techniques detected" << std::endl;
    } else if (total_patterns >= 3) {
        std::cout << "  VERDICT: SUSPICIOUS - Several obfuscation patterns found" << std::endl;
    } else if (total_patterns > 0) {
        std::cout << "  VERDICT: POTENTIALLY SUSPICIOUS - Some patterns detected" << std::endl;
    } else {
        std::cout << "  VERDICT: CLEAN - No suspicious patterns detected" << std::endl;
    }
    
    return 0;
}
EOF

echo "Compiling enhanced static scanner test..."
g++ -std=c++17 -I/home/aadesh/Desktop/Shadow/core/include \
    /tmp/test_enhanced_scanner.cpp \
    /home/aadesh/Desktop/Shadow/core/src/static_scanner.cpp \
    -o /tmp/test_enhanced_scanner

if [ $? -eq 0 ]; then
    echo "Running enhanced static analysis on advanced threat package..."
    /tmp/test_enhanced_scanner "$TEST_DIR"
else
    echo "Failed to compile test program"
fi

# Cleanup
rm -rf "$TEST_DIR"
rm -f /tmp/test_enhanced_scanner /tmp/test_enhanced_scanner.cpp

echo
echo "=== Enhanced Demo Complete ==="