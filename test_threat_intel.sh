#!/bin/bash

echo "=== Expanded Threat Intelligence Test ==="
echo
echo "Testing enhanced C2 detection and CDN allowlisting..."
echo

# Create a simple test program to validate threat intelligence
cat > /tmp/test_threat_intel.cpp << 'EOF'
#include "/home/aadesh/Desktop/Shadow/core/include/threat_intel.h"
#include <iostream>
#include <vector>

int main() {
    std::cout << "=== THREAT INTELLIGENCE VALIDATION ===" << std::endl;
    
    // Test malicious domains (should be flagged)
    std::vector<std::string> malicious_tests = {
        // Original C2s
        "sfrclak.com",
        "git-tanstack.com",
        
        // New malicious domains
        "c2server.net",
        "evil-command.net",
        "backdoor-host.org",
        
        // Tunnel services (commonly abused)
        "test.ngrok.io",
        "malware.localtunnel.me",
        
        // Webhooks (data exfiltration)
        "webhook.site",
        "malicious.requestbin.com",
        
        // File sharing (exfiltration)
        "transfer.sh",
        "0x0.st",
        
        // URL shorteners
        "bit.ly",
        "tinyurl.com"
    };
    
    // Test trusted CDNs (should be allowed)
    std::vector<std::string> trusted_tests = {
        // npm ecosystem
        "registry.npmjs.org",
        "unpkg.com",
        "cdn.jsdelivr.net",
        
        // GitHub
        "api.github.com",
        "raw.githubusercontent.com",
        
        // Major CDNs
        "104.16.10.34",    // Cloudflare
        "151.101.1.140",   // Fastly  
        "185.199.108.153", // GitHub
        "52.84.124.12",    // AWS CloudFront
        "23.32.15.20",     // Akamai
        
        // Cloud providers
        "s3.amazonaws.com",
        "storage.googleapis.com"
    };
    
    // Test malicious IPs (should be flagged)
    std::vector<std::string> malicious_ip_tests = {
        // Original IPs
        "185.220.101.47",
        "45.142.212.100",
        
        // New malicious IPs
        "185.220.101.49",
        "91.92.255.81",
        "103.224.182.251",
        "5.188.86.22"
    };
    
    std::cout << "\n--- MALICIOUS DOMAIN DETECTION ---" << std::endl;
    int malicious_detected = 0;
    for (const auto& domain : malicious_tests) {
        bool is_malicious = ThreatIntel::is_malicious(domain);
        std::cout << (is_malicious ? "✓ BLOCKED" : "✗ MISSED ") 
                  << " : " << domain << std::endl;
        if (is_malicious) malicious_detected++;
    }
    
    std::cout << "\n--- TRUSTED CDN ALLOWLIST ---" << std::endl;
    int trusted_allowed = 0;
    for (const auto& cdn : trusted_tests) {
        bool is_trusted = ThreatIntel::is_trusted_cdn(cdn);
        std::cout << (is_trusted ? "✓ ALLOWED" : "✗ BLOCKED") 
                  << " : " << cdn << std::endl;
        if (is_trusted) trusted_allowed++;
    }
    
    std::cout << "\n--- MALICIOUS IP DETECTION ---" << std::endl;
    int malicious_ips_detected = 0;
    for (const auto& ip : malicious_ip_tests) {
        bool is_malicious = ThreatIntel::is_malicious(ip);
        std::cout << (is_malicious ? "✓ BLOCKED" : "✗ MISSED ") 
                  << " : " << ip << std::endl;
        if (is_malicious) malicious_ips_detected++;
    }
    
    std::cout << "\n--- SUMMARY ---" << std::endl;
    std::cout << "Malicious domains detected: " << malicious_detected 
              << "/" << malicious_tests.size() << std::endl;
    std::cout << "Trusted CDNs allowed: " << trusted_allowed 
              << "/" << trusted_tests.size() << std::endl;
    std::cout << "Malicious IPs detected: " << malicious_ips_detected 
              << "/" << malicious_ip_tests.size() << std::endl;
    
    double malicious_rate = (double)malicious_detected / malicious_tests.size() * 100;
    double trusted_rate = (double)trusted_allowed / trusted_tests.size() * 100;
    double ip_rate = (double)malicious_ips_detected / malicious_ip_tests.size() * 100;
    
    std::cout << "\nDetection rates:" << std::endl;
    std::cout << "• Malicious domains: " << malicious_rate << "%" << std::endl;
    std::cout << "• Trusted CDNs: " << trusted_rate << "%" << std::endl;
    std::cout << "• Malicious IPs: " << ip_rate << "%" << std::endl;
    
    if (malicious_rate >= 90 && trusted_rate >= 90 && ip_rate >= 90) {
        std::cout << "\n✅ THREAT INTELLIGENCE: EXCELLENT" << std::endl;
    } else if (malicious_rate >= 80 && trusted_rate >= 80 && ip_rate >= 80) {
        std::cout << "\n⚠️  THREAT INTELLIGENCE: GOOD" << std::endl;
    } else {
        std::cout << "\n❌ THREAT INTELLIGENCE: NEEDS IMPROVEMENT" << std::endl;
    }
    
    return 0;
}
EOF

echo "Compiling threat intelligence test..."
g++ -std=c++17 -I/home/aadesh/Desktop/Shadow/core/include \
    /tmp/test_threat_intel.cpp \
    /home/aadesh/Desktop/Shadow/core/src/threat_intel.cpp \
    -o /tmp/test_threat_intel

if [ $? -eq 0 ]; then
    echo "Running threat intelligence validation..."
    /tmp/test_threat_intel
else
    echo "Failed to compile test program"
fi

# Cleanup
rm -f /tmp/test_threat_intel /tmp/test_threat_intel.cpp

echo
echo "=== Threat Intelligence Test Complete ==="