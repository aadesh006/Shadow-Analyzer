// tests/test_threat_intel.cpp
//
// Unit tests for ThreatIntel::is_trusted_cdn() and ThreatIntel::is_malicious().
// These are pure C++ string-matching functions — no kernel, no root, no eBPF required.
//
// Run:  ./shadow_tests [threat_intel]

#include "catch2/catch_amalgamated.hpp"
#include "../core/include/threat_intel.h"

// ============================================================
// is_trusted_cdn()
// ============================================================
TEST_CASE("is_trusted_cdn — known CDN domains are trusted", "[threat_intel]") {
    CHECK(ThreatIntel::is_trusted_cdn("registry.npmjs.org"));
    CHECK(ThreatIntel::is_trusted_cdn("npmjs.com"));
    CHECK(ThreatIntel::is_trusted_cdn("npmjs.org"));
    CHECK(ThreatIntel::is_trusted_cdn("github.com"));
    CHECK(ThreatIntel::is_trusted_cdn("raw.githubusercontent.com"));
    CHECK(ThreatIntel::is_trusted_cdn("ghcr.io"));
    CHECK(ThreatIntel::is_trusted_cdn("nodejs.org"));
    CHECK(ThreatIntel::is_trusted_cdn("cloudflare.com"));
    CHECK(ThreatIntel::is_trusted_cdn("fastly.net"));
    CHECK(ThreatIntel::is_trusted_cdn("fastly.com"));
    CHECK(ThreatIntel::is_trusted_cdn("amazonaws.com"));
    CHECK(ThreatIntel::is_trusted_cdn("s3.amazonaws.com"));
    CHECK(ThreatIntel::is_trusted_cdn("cloudfront.net"));
}

TEST_CASE("is_trusted_cdn — Cloudflare 104.16.0.0/12 IP range", "[threat_intel]") {
    // All of 104.16.x through 104.31.x should be trusted
    CHECK(ThreatIntel::is_trusted_cdn("104.16.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("104.17.255.255"));
    CHECK(ThreatIntel::is_trusted_cdn("104.18.10.5"));
    CHECK(ThreatIntel::is_trusted_cdn("104.19.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.20.1.1"));
    CHECK(ThreatIntel::is_trusted_cdn("104.21.50.100"));
    CHECK(ThreatIntel::is_trusted_cdn("104.22.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.23.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.24.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.25.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.26.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.27.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.28.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.29.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.30.0.0"));
    CHECK(ThreatIntel::is_trusted_cdn("104.31.255.255"));

    // 104.32.x is outside /12 — should NOT be trusted
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("104.32.0.1"));
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("104.15.255.255"));
}

TEST_CASE("is_trusted_cdn — Cloudflare 172.64.0.0/13 IP range", "[threat_intel]") {
    CHECK(ThreatIntel::is_trusted_cdn("172.64.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("172.65.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("172.66.100.50"));
    CHECK(ThreatIntel::is_trusted_cdn("172.67.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("172.68.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("172.69.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("172.70.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("172.71.255.255"));

    // Outside /13
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("172.72.0.1"));
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("172.63.255.255"));
}

TEST_CASE("is_trusted_cdn — other Cloudflare ranges", "[threat_intel]") {
    CHECK(ThreatIntel::is_trusted_cdn("162.158.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("188.114.96.1"));
    CHECK(ThreatIntel::is_trusted_cdn("190.93.240.1"));
    CHECK(ThreatIntel::is_trusted_cdn("197.234.240.1"));
    CHECK(ThreatIntel::is_trusted_cdn("198.41.128.1"));
    CHECK(ThreatIntel::is_trusted_cdn("198.41.143.255"));
    // Just outside the /13 upper boundary
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("198.41.144.1"));
}

TEST_CASE("is_trusted_cdn — Fastly CDN (151.101.x.x)", "[threat_intel]") {
    CHECK(ThreatIntel::is_trusted_cdn("151.101.0.1"));
    CHECK(ThreatIntel::is_trusted_cdn("151.101.128.204"));
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("151.100.0.1"));
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("151.102.0.1"));
}

TEST_CASE("is_trusted_cdn — GitHub API/CDN ranges", "[threat_intel]") {
    CHECK(ThreatIntel::is_trusted_cdn("140.82.112.3"));
    CHECK(ThreatIntel::is_trusted_cdn("185.199.108.153"));
    CHECK(ThreatIntel::is_trusted_cdn("192.30.252.1"));
    CHECK(ThreatIntel::is_trusted_cdn("192.30.255.255"));
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("192.30.251.255"));
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("192.31.0.1"));
}

TEST_CASE("is_trusted_cdn — random IPs are not trusted", "[threat_intel]") {
    // Regression: these were wrongly trusted before because 1.1.1.1 and
    // 104.16.1.34 were in the ip_blocklist, implying they were considered known
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("1.1.1.1"));        // Cloudflare DNS — not CDN
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("8.8.8.8"));        // Google DNS
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("185.220.101.47")); // known C2
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("45.142.212.100")); // known C2
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("10.0.0.1"));       // private
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("192.168.1.1"));    // private
    CHECK_FALSE(ThreatIntel::is_trusted_cdn("evil.example.com"));
}

// ============================================================
// is_malicious()
// ============================================================
TEST_CASE("is_malicious — known C2 domains flagged", "[threat_intel]") {
    CHECK(ThreatIntel::is_malicious("sfrclak.com"));          // axios attack C2
    CHECK(ThreatIntel::is_malicious("git-tanstack.com"));     // TanStack attack C2
    CHECK(ThreatIntel::is_malicious("getsession.org"));
}

TEST_CASE("is_malicious — tunnel/reverse-proxy services flagged", "[threat_intel]") {
    CHECK(ThreatIntel::is_malicious("abc123.ngrok.io"));
    CHECK(ThreatIntel::is_malicious("ngrok-free.app"));
    CHECK(ThreatIntel::is_malicious("myapp.localtunnel.me"));
    CHECK(ThreatIntel::is_malicious("serveo.net"));
    CHECK(ThreatIntel::is_malicious("pagekite.me"));
    CHECK(ThreatIntel::is_malicious("bore.pub"));
    CHECK(ThreatIntel::is_malicious("telebit.io"));
}

TEST_CASE("is_malicious — webhook/data-capture services flagged", "[threat_intel]") {
    CHECK(ThreatIntel::is_malicious("requestbin.net"));
    CHECK(ThreatIntel::is_malicious("requestbin.com"));
    CHECK(ThreatIntel::is_malicious("webhook.site"));
    CHECK(ThreatIntel::is_malicious("pipedream.net"));
    CHECK(ThreatIntel::is_malicious("burpcollaborator.net"));
    CHECK(ThreatIntel::is_malicious("oastify.com"));
    CHECK(ThreatIntel::is_malicious("interact.sh"));
    CHECK(ThreatIntel::is_malicious("canarytokens.com"));
    CHECK(ThreatIntel::is_malicious("webhook.run"));
}

TEST_CASE("is_malicious — known C2 raw IPs flagged", "[threat_intel]") {
    // These were the bug: before the fix, is_malicious() only checked domain
    // names but observer.cpp always passed raw IP strings, so C2 IP detection
    // never fired. These tests verify the fix works.
    CHECK(ThreatIntel::is_malicious("185.220.101.47"));
    CHECK(ThreatIntel::is_malicious("185.220.101.34"));
    CHECK(ThreatIntel::is_malicious("185.220.101.35"));
    CHECK(ThreatIntel::is_malicious("185.220.101.36"));
    CHECK(ThreatIntel::is_malicious("185.220.101.48"));
    CHECK(ThreatIntel::is_malicious("45.142.212.100"));
    CHECK(ThreatIntel::is_malicious("91.92.255.80"));
    CHECK(ThreatIntel::is_malicious("194.165.16.29"));
}

TEST_CASE("is_malicious — legitimate IPs and domains are NOT flagged", "[threat_intel]") {
    // Regression: Cloudflare DNS and CDN IPs must never be marked malicious
    CHECK_FALSE(ThreatIntel::is_malicious("1.1.1.1"));
    CHECK_FALSE(ThreatIntel::is_malicious("104.16.1.34"));
    CHECK_FALSE(ThreatIntel::is_malicious("151.101.128.204"));
    CHECK_FALSE(ThreatIntel::is_malicious("registry.npmjs.org"));
    CHECK_FALSE(ThreatIntel::is_malicious("github.com"));
    CHECK_FALSE(ThreatIntel::is_malicious("8.8.8.8"));
    CHECK_FALSE(ThreatIntel::is_malicious("127.0.0.1"));
    CHECK_FALSE(ThreatIntel::is_malicious("192.168.1.1"));
    CHECK_FALSE(ThreatIntel::is_malicious("10.0.0.1"));
    CHECK_FALSE(ThreatIntel::is_malicious("example.com"));
}

TEST_CASE("is_malicious — subdomain matching works correctly", "[threat_intel]") {
    // Subdomains of known-bad domains should match
    CHECK(ThreatIntel::is_malicious("payload.sfrclak.com"));
    CHECK(ThreatIntel::is_malicious("c2.git-tanstack.com"));
    CHECK(ThreatIntel::is_malicious("a1b2c3.ngrok.io"));

    // But unrelated domains that happen to contain a substring should not
    // (none of our known-bad entries are short enough to be a substring risk,
    //  but verify the most likely candidates)
    CHECK_FALSE(ThreatIntel::is_malicious("notngrok.io"));
    CHECK_FALSE(ThreatIntel::is_malicious("my-ngrok-alternative.com"));
}
