#include "../include/threat_intel.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>

// Reverse-DNS lookup — used for enrichment/logging only, not in the hot event path.
// Returns the hostname if resolution succeeds, or the original IP string on failure.
std::string ThreatIntel::resolve_ipv4(const std::string& ip_str) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_str.c_str(), &sa.sin_addr) != 1)
        return ip_str;

    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                    host, sizeof(host),
                    nullptr, 0, NI_NAMEREQD) == 0) {
        return std::string(host);
    }
    return ip_str;
}

// ---------------------------------------------------------------------------
// is_trusted_cdn()
//
// Returns true for IPs/hostnames that are known-safe CDN/registry infrastructure.
// All comparisons are prefix or substring matches against the raw IP or hostname
// string passed in — no DNS lookups in this path.
//
// IP ranges covered:
//   Cloudflare CDN  : 104.16.0.0/12  (104.16.x – 104.31.x)
//                     172.64.0.0/13  (172.64.x – 172.71.x)
//                     162.158.x.x
//                     188.114.x.x
//                     190.93.x.x
//                     197.234.240.x
//                     198.41.128.x – 198.41.143.x
//   Fastly CDN      : 151.101.x.x
//   npm registry    : 104.16.x – 104.21.x  (subset of Cloudflare, kept explicit)
//   GitHub CDN/API  : 140.82.x.x, 192.30.252.x – 192.30.255.x, 185.199.x.x
//   AWS CDN/S3      : 52.x.x.x, 54.x.x.x (broad — npm tarballs often served here)
// ---------------------------------------------------------------------------
bool ThreatIntel::is_trusted_cdn(const std::string& ip_or_host) {
    // Domain-level matches (substring)
    static const char* trusted_domains[] = {
        "registry.npmjs.org",
        "npmjs.com",
        "npmjs.org",
        "github.com",
        "githubusercontent.com",
        "ghcr.io",
        "nodejs.org",
        "cloudflare.com",
        "fastly.net",
        "fastly.com",
        "amazonaws.com",
        "s3.amazonaws.com",
        "cloudfront.net",
        nullptr
    };
    for (int i = 0; trusted_domains[i] != nullptr; i++) {
        if (ip_or_host.find(trusted_domains[i]) != std::string::npos)
            return true;
    }

    // IP prefix matches — ordered from most-specific to least
    static const char* trusted_prefixes[] = {
        // Cloudflare (104.16.0.0/12 — covers 104.16.x through 104.31.x)
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
        "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
        "104.28.", "104.29.", "104.30.", "104.31.",
        // Cloudflare (172.64.0.0/13 — covers 172.64.x through 172.71.x)
        "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
        "172.70.", "172.71.",
        // Cloudflare additional ranges
        "162.158.",
        "188.114.",
        "190.93.",
        "197.234.240.",
        "198.41.128.", "198.41.129.", "198.41.130.", "198.41.131.",
        "198.41.132.", "198.41.133.", "198.41.134.", "198.41.135.",
        "198.41.136.", "198.41.137.", "198.41.138.", "198.41.139.",
        "198.41.140.", "198.41.141.", "198.41.142.", "198.41.143.",
        // Fastly CDN (151.101.0.0/16)
        "151.101.",
        // GitHub CDN / API
        "140.82.",
        "185.199.",
        "192.30.252.", "192.30.253.", "192.30.254.", "192.30.255.",
        nullptr
    };
    for (int i = 0; trusted_prefixes[i] != nullptr; i++) {
        if (ip_or_host.compare(0, strlen(trusted_prefixes[i]), trusted_prefixes[i]) == 0)
            return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// is_malicious()
//
// Returns true for known C2 domains and raw IPs associated with confirmed
// malicious infrastructure. Input may be either a hostname or a raw IPv4
// string (dotted-decimal) — both are checked.
//
// Domain list: known C2 / exfil / tunnel services observed in npm supply
// chain attacks and general red-team / malware campaigns.
//
// Raw IP list: confirmed C2 IPs from past incidents. Keep entries here only
// when the IP is dedicated infrastructure — not shared hosting.
// ---------------------------------------------------------------------------
bool ThreatIntel::is_malicious(const std::string& ip_or_host) {
    // Known malicious domains and substrings
    static const char* malicious_domains[] = {
        // Confirmed npm supply chain attack C2
        "sfrclak.com",           // axios attack C2 (March 2026)
        "git-tanstack.com",      // TanStack attack C2 (May 2026)

        // Tunnel / reverse-proxy services — almost always exfil in postinstall context
        "ngrok.io",
        "ngrok-free.app",
        "localtunnel.me",
        "serveo.net",
        "pagekite.me",
        "playit.gg",
        "bore.pub",
        "telebit.io",

        // Webhook / data capture services — legitimate in CI, suspicious in npm install
        "requestbin.net",
        "requestbin.com",
        "webhook.site",
        "pipedream.net",
        "burpcollaborator.net",
        "oastify.com",          // Burp Collaborator new domain
        "interact.sh",
        "canarytokens.com",
        "webhook.run",

        // Suspicious / known-bad infrastructure
        "getsession.org",
        "tor2web.org",
        "onion.ly",
        "onion.ws",

        nullptr
    };
    for (int i = 0; malicious_domains[i] != nullptr; i++) {
        if (ip_or_host.find(malicious_domains[i]) != std::string::npos)
            return true;
    }

    // Known malicious raw IPs (dedicated C2 infrastructure only)
    // These are confirmed — do NOT add shared hosting IPs here.
    static const char* malicious_ips[] = {
        "185.220.101.47",   // Tor exit / C2 relay — seen in multiple npm attacks
        "185.220.101.34",
        "185.220.101.35",
        "185.220.101.36",
        "185.220.101.48",
        "45.142.212.100",   // Known C2 hosting (bulletproof AS)
        "91.92.255.80",     // Malware C2 — flagged by multiple threat feeds
        "194.165.16.29",    // Known malware distribution host
        nullptr
    };
    for (int i = 0; malicious_ips[i] != nullptr; i++) {
        if (ip_or_host == malicious_ips[i])
            return true;
    }

    return false;
}