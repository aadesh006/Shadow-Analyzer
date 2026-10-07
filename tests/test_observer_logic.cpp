// tests/test_observer_logic.cpp
//
// Tests for the event classification logic that lives in observer.cpp.
// We extract the classification rules into testable form here without
// needing a live Observer instance (which requires root + eBPF).
//
// Specifically tests:
//   - Host process noise filter (comm name filtering)
//   - Process spawn suspicious binary detection
//   - Expected vs unexpected process detection
//
// Run:  ./shadow_tests [observer]

#include "catch2/catch_amalgamated.hpp"
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Replicate the classification helpers from observer.cpp so we can test them
// in isolation without pulling in libbpf/eBPF headers.
// ---------------------------------------------------------------------------

static bool is_host_noise(const std::string& comm) {
    // Mirrors the noise filter in Observer::handle_event()
    return (comm == "systemd-resolve" ||
            comm == "systemd"         ||
            comm == "shadow"          ||
            comm == "code"            ||
            comm == "Chrome_ChildIOT" ||
            comm == "chrome"          ||
            comm == "sh"              ||
            comm == "umount"          ||
            comm == "rm");
}

static bool is_expected_process(const std::string& binary) {
    // Mirrors the is_expected check in the PROCESS event handler
    return (binary.find("npm")  != std::string::npos ||
            binary.find("node") != std::string::npos);
}

static bool is_suspicious_downloader(const std::string& binary) {
    // Mirrors the is_downloader check that triggers [ALERT]
    return (binary.find("curl")   != std::string::npos ||
            binary.find("wget")   != std::string::npos ||
            binary.find("python") != std::string::npos ||
            binary.find("perl")   != std::string::npos ||
            binary.find("ruby")   != std::string::npos ||
            binary.find("bash")   != std::string::npos);
}

// ============================================================
// Host process noise filter
// ============================================================
TEST_CASE("noise filter — system processes are filtered out", "[observer]") {
    CHECK(is_host_noise("systemd-resolve"));
    CHECK(is_host_noise("systemd"));
    CHECK(is_host_noise("shadow"));
    CHECK(is_host_noise("code"));
    CHECK(is_host_noise("Chrome_ChildIOT"));
    CHECK(is_host_noise("chrome"));
    CHECK(is_host_noise("sh"));
    CHECK(is_host_noise("umount"));
    CHECK(is_host_noise("rm"));
}

TEST_CASE("noise filter — sandbox processes are NOT filtered", "[observer]") {
    CHECK_FALSE(is_host_noise("npm"));
    CHECK_FALSE(is_host_noise("node"));
    CHECK_FALSE(is_host_noise("curl"));
    CHECK_FALSE(is_host_noise("wget"));
    CHECK_FALSE(is_host_noise("python3"));
    CHECK_FALSE(is_host_noise("bash"));
    CHECK_FALSE(is_host_noise("malware"));
    CHECK_FALSE(is_host_noise(""));
}

TEST_CASE("noise filter — comm name is exact match (not substring)", "[observer]") {
    // 'sh' should filter, but 'ssh' or 'bash' should not
    CHECK(is_host_noise("sh"));
    CHECK_FALSE(is_host_noise("bash"));
    CHECK_FALSE(is_host_noise("ssh"));
    CHECK_FALSE(is_host_noise("dash"));

    // 'rm' should filter, but 'nrm' or 'crm' should not
    CHECK(is_host_noise("rm"));
    CHECK_FALSE(is_host_noise("nrm"));
    CHECK_FALSE(is_host_noise("frm"));
}

// ============================================================
// Process spawn — expected vs unexpected
// ============================================================
TEST_CASE("process spawn — npm and node are expected", "[observer]") {
    CHECK(is_expected_process("/usr/bin/npm"));
    CHECK(is_expected_process("/usr/local/bin/node"));
    CHECK(is_expected_process("npm"));
    CHECK(is_expected_process("node"));
    // node_modules scripts that contain 'node' in their path
    CHECK(is_expected_process("/tmp/node_modules/.bin/something"));
}

TEST_CASE("process spawn — downloaders are NOT expected processes", "[observer]") {
    CHECK_FALSE(is_expected_process("/usr/bin/curl"));
    CHECK_FALSE(is_expected_process("/usr/bin/wget"));
    CHECK_FALSE(is_expected_process("/usr/bin/python3"));
    CHECK_FALSE(is_expected_process("/bin/bash"));
    CHECK_FALSE(is_expected_process("/usr/bin/perl"));
    CHECK_FALSE(is_expected_process("/usr/bin/ruby"));
}

// ============================================================
// Suspicious downloader detection
// ============================================================
TEST_CASE("downloader detection — known downloader binaries flagged", "[observer]") {
    CHECK(is_suspicious_downloader("/usr/bin/curl"));
    CHECK(is_suspicious_downloader("/usr/bin/wget"));
    CHECK(is_suspicious_downloader("/usr/bin/python3"));
    CHECK(is_suspicious_downloader("/usr/bin/python"));
    CHECK(is_suspicious_downloader("/usr/bin/perl"));
    CHECK(is_suspicious_downloader("/usr/bin/ruby"));
    CHECK(is_suspicious_downloader("/bin/bash"));
}

TEST_CASE("downloader detection — npm/node not flagged as downloaders", "[observer]") {
    CHECK_FALSE(is_suspicious_downloader("/usr/bin/npm"));
    CHECK_FALSE(is_suspicious_downloader("/usr/bin/node"));
    CHECK_FALSE(is_suspicious_downloader("/usr/local/bin/node"));
}

TEST_CASE("downloader detection — path substring matching works", "[observer]") {
    // A binary named 'pycurl' contains 'curl' — intentionally flagged
    CHECK(is_suspicious_downloader("/usr/bin/pycurl"));
    // A shell script that invokes bash via path
    CHECK(is_suspicious_downloader("/usr/local/bin/bash"));
}

TEST_CASE("downloader detection — benign binaries not flagged", "[observer]") {
    CHECK_FALSE(is_suspicious_downloader("/usr/bin/make"));
    CHECK_FALSE(is_suspicious_downloader("/usr/bin/gcc"));
    CHECK_FALSE(is_suspicious_downloader("/bin/sh"));
    CHECK_FALSE(is_suspicious_downloader("esbuild"));
    CHECK_FALSE(is_suspicious_downloader("tsc"));
}

// ============================================================
// Combined: unexpected + downloader = ALERT
// ============================================================
TEST_CASE("alert logic — unexpected downloader triggers ALERT verdict", "[observer]") {
    struct TestCase {
        std::string binary;
        bool should_alert;
    };

    std::vector<TestCase> cases = {
        { "/usr/bin/curl",    true  },   // unexpected + downloader → ALERT
        { "/usr/bin/wget",    true  },   // unexpected + downloader → ALERT
        { "/usr/bin/python3", true  },   // unexpected + downloader → ALERT
        { "/usr/bin/npm",     false },   // expected → no alert
        { "/usr/bin/node",    false },   // expected → no alert
        { "/usr/bin/make",    false },   // unexpected but not downloader → [PROCESS] only, no ALERT
        { "/usr/bin/gcc",     false },   // unexpected but not downloader → [PROCESS] only, no ALERT
    };

    for (const auto& tc : cases) {
        bool unexpected = !is_expected_process(tc.binary);
        bool downloader = is_suspicious_downloader(tc.binary);
        bool alert = unexpected && downloader;

        INFO("Binary: " << tc.binary);
        CHECK(alert == tc.should_alert);
    }
}
