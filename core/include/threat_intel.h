#pragma once
#include <string>

class ThreatIntel {
public:
    static std::string resolve_ipv4(const std::string& ip_str);
    static bool is_malicious(const std::string& hostname);
    static bool is_trusted_cdn(const std::string& hostname);
};