#include "../include/threat_intel.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

std::string ThreatIntel::resolve_ipv4(const std::string& ip_str) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str.c_str(), &sa.sin_addr);

    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
        return std::string(host);
    }
    return "UNKNOWN IP";
}

bool ThreatIntel::is_malicious(const std::string& hostname) {
    std::vector<std::string> malicious_domains = {
        "evil.com", "pastebin.com", "ngrok.io", "localtunnel.me", 
        "requestbin.net", "burpcollaborator.net", "interact.sh"
    };

    for (const auto& domain : malicious_domains) {
        if (hostname.find(domain) != std::string::npos) return true;
    }
    return false;
}