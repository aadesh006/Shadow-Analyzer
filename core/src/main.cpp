#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/sandbox.h"
#include "../include/observer.h"

// ANSI Terminal Colors
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_BOLD    "\033[1m"

// ---------------------------------------------------------------------------
// print_diff()
//
// Walks the OverlayFS upper directory and prints every file the package
// created or modified during install. Deletions appear as whiteout files
// (prefixed with ".wh.") in the upper dir — we detect and label them.
//
// upper_dir: host-side path to the OverlayFS upper layer.
// ---------------------------------------------------------------------------
static void print_diff(const std::string& upper_dir) {
    if (upper_dir.empty()) {
        std::cout << COLOR_YELLOW
                  << "[DIFF] OverlayFS was not available — filesystem diff skipped."
                  << COLOR_RESET << std::endl;
        return;
    }

    std::cout << "\n[Shadow] ══════════════ FILESYSTEM DELTA ══════════════\n";
    std::cout << COLOR_BOLD << "[DIFF] Files written or modified by the package:\n" << COLOR_RESET;

    // Recursive lambda via std::function to walk the upper dir
    int file_count = 0;
    int del_count  = 0;

    std::function<void(const std::string&, const std::string&)> walk =
        [&](const std::string& dir, const std::string& rel_prefix) {
            DIR* d = opendir(dir.c_str());
            if (!d) return;

            struct dirent* ent;
            while ((ent = readdir(d)) != nullptr) {
                std::string name(ent->d_name);
                if (name == "." || name == "..") continue;

                std::string full_path = dir + "/" + name;
                std::string rel_path  = rel_prefix + "/" + name;

                // OverlayFS whiteout: file was deleted by the package
                if (name.substr(0, 4) == ".wh.") {
                    std::string deleted = rel_prefix + "/" + name.substr(4);
                    std::cout << "  " COLOR_RED "[-] DELETED" COLOR_RESET
                              << "  " << deleted << std::endl;
                    del_count++;
                    continue;
                }

                struct stat st;
                if (lstat(full_path.c_str(), &st) != 0) continue;

                if (S_ISDIR(st.st_mode)) {
                    walk(full_path, rel_path);
                } else {
                    // Format size
                    std::string size_str;
                    if (st.st_size < 1024)
                        size_str = std::to_string(st.st_size) + "B";
                    else if (st.st_size < 1024 * 1024)
                        size_str = std::to_string(st.st_size / 1024) + "KB";
                    else
                        size_str = std::to_string(st.st_size / (1024 * 1024)) + "MB";

                    std::cout << "  " COLOR_GREEN "[+]" COLOR_RESET
                              << " " << rel_path
                              << " (" << size_str << ")" << std::endl;
                    file_count++;
                }
            }
            closedir(d);
        };

    walk(upper_dir, "");

    if (file_count == 0 && del_count == 0) {
        std::cout << "  (no filesystem changes detected)" << std::endl;
    } else {
        std::cout << "\n  " << file_count << " file(s) written/modified, "
                  << del_count << " file(s) deleted." << std::endl;
    }
}

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: shadow analyze <package>[@<version>]" << std::endl;
        std::cerr << "       shadow analyze <path/to/package.tgz>" << std::endl;
        return 1;
    }

    std::string command = argv[1];
    std::string target  = argv[2];

    // If the target is a local tarball path, rewrite it to /tmp/<filename>
    // so it resolves correctly inside the pivot_root jail.
    std::string npm_target = target;
    if (!target.empty() && target[0] == '/') {
        std::string filename = target.substr(target.find_last_of('/') + 1);
        if (filename.find(".tgz") != std::string::npos ||
            filename.find(".tar") != std::string::npos) {
            npm_target = "/tmp/" + filename;
        }
    }

    if (command == "analyze") {
        std::cout << "=== Shadow Analyzer v1.0 ===" << std::endl;
        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                  << " Target: " << target << "\n" << std::endl;

        // Load and attach eBPF probes
        Observer kernel_observer;
        if (!kernel_observer.start()) {
            std::cerr << "Failed to initialize kernel security module. Aborting." << std::endl;
            return 1;
        }

        Sandbox sandbox;
        std::string pkg_manager = "npm";

        std::vector<std::string> npm_args = {
            "install",
            npm_target,
            "--ignore-scripts=false",
            "--no-audit",
            "--no-fund",
            "--cache=/tmp/.npm",
            "--fetch-timeout=5000",
        };

        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                  << " Launching " << pkg_manager << " inside sandbox..." << std::endl;

        int sandbox_status = sandbox.run(pkg_manager, npm_args,
            [&kernel_observer](pid_t child_pid) {
                kernel_observer.register_sandbox_pid(child_pid);
            });

        // Drain the ring buffer for any final in-flight events
        std::cout << "[Shadow] Sweeping ring buffer for final events..." << std::endl;
        sleep(2);

        kernel_observer.stop();

        // Print filesystem diff before the verdict
        print_diff(sandbox.overlay_upper_dir);

        std::cout << "\n[Shadow] ══════════════ ANALYSIS COMPLETE ══════════════\n";

        if (sandbox_status == 124) {
            std::cout << COLOR_YELLOW
                      << "[RESULT] TIMEOUT — Package stalled the sandbox. Requires manual review."
                      << COLOR_RESET << std::endl;
        } else if (kernel_observer.threat_detected) {
            std::cout << COLOR_RED
                      << "[RESULT] MALICIOUS — "
                      << kernel_observer.threat_description
                      << "\n         DO NOT INSTALL THIS PACKAGE."
                      << COLOR_RESET << std::endl;
        } else {
            std::cout << COLOR_GREEN
                      << "[RESULT] CLEAN — No threats detected."
                      << COLOR_RESET << std::endl;
        }

    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
