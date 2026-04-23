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
    if (hostname.find("evil.com") != std::string::npos) return true;
    if (hostname.find("pastebin.com") != std::string::npos) return true;
    return false;
}