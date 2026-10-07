// tests/test_rules_parser.cpp
//
// Tests for the shadow_rules.conf and shadow_ip_blocklist.conf parsing logic.
// These validate that the files load correctly and contain the expected entries,
// without requiring root or eBPF (we read the files directly here).
//
// Run:  ./shadow_tests [rules]

#include "catch2/catch_amalgamated.hpp"
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <algorithm>

// ---------------------------------------------------------------------------
// Helper: load a conf file into a set of non-comment, non-blank lines.
// Mirrors the parsing logic in inject_dynamic_rules() / inject_ip_blocklist().
// ---------------------------------------------------------------------------
static std::set<std::string> load_conf(const std::string& path) {
    std::set<std::string> entries;
    std::ifstream f(path);
    if (!f.is_open()) return entries;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        entries.insert(line);
    }
    return entries;
}

// Paths relative to the project root — tests are run from build/
static const std::string RULES_CONF      = "../shadow_rules.conf";
static const std::string IP_BLOCKLIST    = "../shadow_ip_blocklist.conf";

// ============================================================
// shadow_rules.conf
// ============================================================
TEST_CASE("shadow_rules.conf — file exists and is parseable", "[rules]") {
    std::ifstream f(RULES_CONF);
    REQUIRE(f.is_open());
}

TEST_CASE("shadow_rules.conf — contains core credential file entries", "[rules]") {
    auto entries = load_conf(RULES_CONF);
    REQUIRE_FALSE(entries.empty());

    // Unix credentials
    CHECK(entries.count("passwd"));
    CHECK(entries.count("shadow"));

    // SSH keys
    CHECK(entries.count("id_rsa"));
    CHECK(entries.count("id_ed25519"));
    CHECK(entries.count("id_ecdsa"));
    CHECK(entries.count("authorized_keys"));

    // AWS
    CHECK(entries.count("credentials"));

    // Generic secrets
    CHECK(entries.count(".env"));
    CHECK(entries.count(".netrc"));
}

TEST_CASE("shadow_rules.conf — no blank or comment-only content entries", "[rules]") {
    // Every loaded entry must be a non-empty, non-comment string
    auto entries = load_conf(RULES_CONF);
    for (const auto& e : entries) {
        CHECK_FALSE(e.empty());
        CHECK(e[0] != '#');
    }
}

TEST_CASE("shadow_rules.conf — no path separators (basenames only)", "[rules]") {
    // The eBPF hook only matches against d_name (basename).
    // Entries with '/' would never match and signal a misconfiguration.
    auto entries = load_conf(RULES_CONF);
    for (const auto& e : entries) {
        INFO("Entry with path separator: " << e);
        CHECK(e.find('/') == std::string::npos);
    }
}

TEST_CASE("shadow_rules.conf — has reasonable entry count", "[rules]") {
    // Sanity: should have more entries than the original 6, but not be
    // so large it would fill the 1024-entry BPF hash map
    auto entries = load_conf(RULES_CONF);
    CHECK(entries.size() >= 10);
    CHECK(entries.size() <= 1000);
}

// ============================================================
// shadow_ip_blocklist.conf
// ============================================================
TEST_CASE("shadow_ip_blocklist.conf — file exists and is parseable", "[rules]") {
    std::ifstream f(IP_BLOCKLIST);
    REQUIRE(f.is_open());
}

TEST_CASE("shadow_ip_blocklist.conf — contains known C2 IPs", "[rules]") {
    auto entries = load_conf(IP_BLOCKLIST);
    REQUIRE_FALSE(entries.empty());

    // axios attack C2
    CHECK(entries.count("185.220.101.47"));
    // TanStack attack C2
    CHECK(entries.count("45.142.212.100"));
}

TEST_CASE("shadow_ip_blocklist.conf — does NOT contain false-positive CDN IPs", "[rules]") {
    // Regression test for the bug where Cloudflare IPs were in the blocklist,
    // causing false MALICIOUS verdicts on legitimate packages.
    auto entries = load_conf(IP_BLOCKLIST);

    CHECK_FALSE(entries.count("1.1.1.1"));       // Cloudflare DNS — was in the original file
    CHECK_FALSE(entries.count("1.0.0.1"));       // Cloudflare DNS secondary
    CHECK_FALSE(entries.count("8.8.8.8"));       // Google DNS
    CHECK_FALSE(entries.count("8.8.4.4"));       // Google DNS secondary
    CHECK_FALSE(entries.count("104.16.1.34"));   // Cloudflare CDN — was in the original file
    CHECK_FALSE(entries.count("151.101.128.204")); // Fastly CDN
    CHECK_FALSE(entries.count("140.82.112.3"));  // GitHub
}

TEST_CASE("shadow_ip_blocklist.conf — all entries are valid IPv4 dotted-decimal", "[rules]") {
    // Mirrors inet_pton validation in inject_ip_blocklist()
    auto entries = load_conf(IP_BLOCKLIST);
    for (const auto& e : entries) {
        // Basic validation: 4 octets separated by dots, each 0-255
        int octets = 0;
        bool valid = true;
        std::string octet;
        std::string ip = e + "."; // sentinel

        for (char c : ip) {
            if (c == '.') {
                if (octet.empty() || octet.size() > 3) { valid = false; break; }
                int val = std::stoi(octet);
                if (val < 0 || val > 255) { valid = false; break; }
                octets++;
                octet.clear();
            } else if (c >= '0' && c <= '9') {
                octet += c;
            } else {
                valid = false; break;
            }
        }
        valid = valid && (octets == 4);

        INFO("Invalid IP entry: " << e);
        CHECK(valid);
    }
}

TEST_CASE("shadow_ip_blocklist.conf — no duplicate entries", "[rules]") {
    // Duplicates waste BPF map slots (limited to 1024)
    std::ifstream f(IP_BLOCKLIST);
    REQUIRE(f.is_open());

    std::vector<std::string> all_lines;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        all_lines.push_back(line);
    }

    std::set<std::string> unique(all_lines.begin(), all_lines.end());
    CHECK(all_lines.size() == unique.size());
}
