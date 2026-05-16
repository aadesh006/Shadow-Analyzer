#include "../include/threat_intel.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

std::string ThreatIntel::resolve_ipv4(const std::string& ip_str) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str.c_str(), &sa.sin_addr);

    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                    host, sizeof(host),
                    NULL, 0, NI_NAMEREQD) == 0) {
        return std::string(host);
    }
    return ip_str;
}

bool ThreatIntel::is_trusted_cdn(const std::string& ip_or_host) {
    static const char* trusted[] = {
        "registry.npmjs.org",
        "githubusercontent.com",
        "github.com",
        "nodejs.org",
        "npmjs.com",
        "cloudflare.com",
        "fastly.net",
        "amazonaws.com",
        "104.16.", "104.17.", "104.18.", "104.19.",
        "104.20.", "104.21.",
        "172.66.", "172.67.",
        nullptr
    };
    for (int i = 0; trusted[i] != nullptr; i++) {
        if (ip_or_host.find(trusted[i]) != std::string::npos)
            return true;
    }
    return false;
}

bool ThreatIntel::is_malicious(const std::string& hostname) {
    static const char* malicious[] = {
        "sfrclak.com",
        "git-tanstack.com",
        "getsession.org",
        "ngrok.io",
        "localtunnel.me",
        "requestbin.net",
        "burpcollaborator.net",
        "interact.sh",
        nullptr
    };
    for (int i = 0; malicious[i] != nullptr; i++) {
        if (hostname.find(malicious[i]) != std::string::npos)
            return true;
    }
    return false;
}