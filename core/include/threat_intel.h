#pragma once
#include <string>
#include <vector>

class ThreatIntel {
public:

    static std::string resolve_ipv4(const std::string& ip_str);
    
    static bool is_malicious(const std::string& hostname);
};