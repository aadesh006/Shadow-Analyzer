#pragma once
#include <string>
#include <vector>
#include <set>

class ThreatIntel {
public:
    static std::string resolve_ipv4(const std::string& ip_str);
    static bool is_malicious(const std::string& hostname);
    static bool is_trusted_cdn(const std::string& hostname);
    
    // Load threat feeds from files
    static bool load_threat_feeds();
    static bool reload_threat_feeds();
    
private:
    // Dynamic threat lists loaded from files
    static std::set<std::string> malicious_ips_;
    static std::set<std::string> malicious_domains_;
    static bool feeds_loaded_;
    
    // Helper to load file
    static bool load_file(const char* filepath, std::set<std::string>& output);
};