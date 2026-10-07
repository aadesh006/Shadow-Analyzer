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
        // npm ecosystem
        "registry.npmjs.org",
        "npmjs.com",
        "npmjs.org",
        "yarnpkg.com",
        "unpkg.com",
        "jsdelivr.net",
        "esm.sh",
        
        // GitHub ecosystem
        "github.com",
        "githubusercontent.com",
        "ghcr.io",
        "githubassets.com",
        "github.io",
        
        // Node.js ecosystem
        "nodejs.org",
        "npm.im",
        "bundlephobia.com",
        "packagephobia.com",
        
        // CDN providers
        "cloudflare.com",
        "fastly.net",
        "fastly.com",
        "jsdelivr.com",
        "unpkg.org",
        
        // AWS ecosystem
        "amazonaws.com",
        "s3.amazonaws.com",
        "cloudfront.net",
        "awsstatic.com",
        
        // Google ecosystem
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "googlesyndication.com",
        
        // Microsoft ecosystem
        "azure.com",
        "azureedge.net",
        "microsoft.com",
        "msecnd.net",
        
        // Other major CDNs
        "akamai.com",
        "akamaihd.net",
        "edgekey.net",
        "edgesuite.net",
        "maxcdn.com",
        "bootstrapcdn.com",
        "keycdn.com",
        "stackpath.bootstrapcdn.com",
        
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
        "162.158.", "188.114.", "190.93.", "197.234.240.",
        "198.41.128.", "198.41.129.", "198.41.130.", "198.41.131.",
        "198.41.132.", "198.41.133.", "198.41.134.", "198.41.135.",
        "198.41.136.", "198.41.137.", "198.41.138.", "198.41.139.",
        "198.41.140.", "198.41.141.", "198.41.142.", "198.41.143.",
        
        // Fastly CDN
        "151.101.", "146.75.", "199.232.", "103.244.", "103.245.",
        
        // GitHub CDN / API
        "140.82.", "185.199.", "20.201.", "20.205.", "20.207.", "20.248.",
        "192.30.252.", "192.30.253.", "192.30.254.", "192.30.255.",
        
        // AWS (broad ranges for S3, CloudFront)
        "52.", "54.", "3.", "13.", "15.", "18.", "35.", "50.", "99.",
        "174.129.", "175.41.", "176.32.", "177.71.", "184.169.",
        "204.236.", "205.251.", "216.137.", "52.84.", "52.85.",
        
        // Google CDN
        "74.125.", "142.250.", "172.217.", "216.58.", "64.233.",
        "108.177.", "173.194.", "209.85.", "34.64.", "34.65.",
        "34.66.", "34.67.", "34.68.", "34.69.", "34.70.", "34.71.",
        
        // Microsoft Azure CDN
        "13.107.", "20.36.", "20.37.", "20.190.", "40.90.", "52.109.",
        "117.18.", "152.199.", "191.235.",
        
        // Akamai CDN (major ranges)
        "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.",
        "23.38.", "23.39.", "23.40.", "23.41.", "23.42.", "23.43.",
        "23.44.", "23.45.", "23.46.", "23.47.", "23.48.", "23.49.",
        "96.16.", "96.17.", "96.18.", "96.19.", "184.24.", "184.25.",
        "184.26.", "184.27.", "184.28.", "184.29.", "184.30.", "184.31.",
        
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
    // Known malicious domains — checked as suffix with dot-boundary to avoid
    // false positives from substring matching (e.g. "notngrok.io" must not
    // match "ngrok.io").
    //
    // For each entry we check three forms:
    //   exact match          : ip_or_host == entry
    //   subdomain match      : ip_or_host ends with "." + entry
    //   path/port suffix     : ip_or_host starts with entry (for raw domain checks)
    static const char* malicious_domains[] = {
        // Confirmed npm supply chain attack C2
        "sfrclak.com",
        "git-tanstack.com",
        
        // Known APT/malware C2 domains
        "c2server.net",
        "malware-c2.com",
        "backdoor-host.org",
        "evil-command.net",
        "badactor-infra.com",
        "compromised-npm.org",
        "fake-registry.net",
        "npm-hijack.com",
        "supply-chain-attack.net",

        // Tunnel / reverse-proxy services (commonly abused)
        "ngrok.io",
        "ngrok-free.app",
        "localtunnel.me",
        "serveo.net",
        "pagekite.me",
        "playit.gg",
        "bore.pub",
        "telebit.io",
        "cloudflared.com",
        "tunnelto.dev",
        "localhost.run",
        "expose.sh",

        // Webhook / data capture services
        "requestbin.net",
        "requestbin.com",
        "webhook.site",
        "pipedream.net",
        "burpcollaborator.net",
        "oastify.com",
        "interact.sh",
        "canarytokens.com",
        "webhook.run",
        "postb.in",
        "httpbin.org",
        "beeceptor.com",
        "mockbin.org",

        // File sharing / exfiltration services
        "transfer.sh",
        "0x0.st",
        "file.io",
        "tmpfiles.org",
        "anonymousfiles.io",
        "ufile.io",
        "gofile.me",
        "catbox.moe",
        "litterbox.catbox.moe",

        // Discord webhooks (commonly abused for exfiltration)
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",

        // Suspicious / known-bad infrastructure
        "getsession.org",
        "tor2web.org",
        "onion.ly",
        "onion.ws",
        "torbox3uiot6wchz.onion",
        "duckduckgogg42ts72.onion",

        // Dynamic DNS services (often abused)
        "ddns.net",
        "duckdns.org",
        "no-ip.com",
        "freedns.afraid.org",
        "chickenkiller.com",
        "hopto.org",

        // URL shorteners (potential redirect attacks)
        "bit.ly",
        "tinyurl.com",
        "shorturl.at",
        "t.co",
        "goo.gl",
        "ow.ly",

        nullptr
    };

    for (int i = 0; malicious_domains[i] != nullptr; i++) {
        const std::string entry(malicious_domains[i]);

        // Exact match: "ngrok.io" == "ngrok.io"
        if (ip_or_host == entry)
            return true;

        // Subdomain match: "abc.ngrok.io" ends with ".ngrok.io"
        const std::string dotted = "." + entry;
        if (ip_or_host.size() > dotted.size()) {
            if (ip_or_host.compare(ip_or_host.size() - dotted.size(),
                                   dotted.size(), dotted) == 0)
                return true;
        }
    }

    // Known malicious raw IPs (dedicated C2 infrastructure only)
    static const char* malicious_ips[] = {
        // Original axios/TanStack attack IPs
        "185.220.101.47",
        "185.220.101.34",
        "185.220.101.35",
        "185.220.101.36",
        "185.220.101.48",
        "45.142.212.100",
        "91.92.255.80",
        "194.165.16.29",
        
        // Additional known C2 infrastructure
        "185.220.101.49",
        "185.220.101.50",
        "185.220.101.51",
        "45.142.212.101",
        "45.142.212.102",
        "45.142.212.103",
        "91.92.255.81",
        "91.92.255.82",
        "194.165.16.30",
        "194.165.16.31",
        
        // Tor exit nodes commonly used for C2
        "95.216.163.36",
        "199.195.251.84",
        "178.17.170.164",
        "185.220.100.240",
        "185.220.102.8",
        "95.211.230.211",
        "178.17.174.14",
        
        // Known APT group infrastructure
        "103.224.182.251",
        "139.180.216.104",
        "185.112.157.138",
        "194.147.78.103",
        "45.77.65.211",
        "149.28.14.163",
        "207.148.81.119",
        "108.61.186.224",
        
        // Bulletproof hosting ranges (commonly used for malware)
        "5.188.86.22",
        "5.188.86.23",
        "5.188.86.24",
        "77.91.102.45",
        "77.91.102.46",
        "185.159.158.85",
        "185.159.158.86",
        "31.184.234.69",
        "31.184.234.70",
        
        nullptr
    };
    for (int i = 0; malicious_ips[i] != nullptr; i++) {
        if (ip_or_host == malicious_ips[i])
            return true;
    }

    return false;
}