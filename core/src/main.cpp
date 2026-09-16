#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/sandbox.h"
#include "../include/observer.h"
#include "../include/apt_analyzer.h"

// ANSI Terminal Colors
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_BOLD    "\033[1m"

// ---------------------------------------------------------------------------
// write_diff_log()
//
// Walks the OverlayFS upper directory and writes the full filesystem delta
// to a log file at /tmp/shadow_diff_<pid>.log instead of flooding the
// terminal. Prints a one-line summary to stdout when done.
//
// upper_dir: host-side path to the OverlayFS upper layer.
// ---------------------------------------------------------------------------
static void write_diff_log(const std::string& upper_dir) {
    if (upper_dir.empty()) {
        std::cout << COLOR_YELLOW
                  << "[DIFF] OverlayFS not available — filesystem diff skipped."
                  << COLOR_RESET << std::endl;
        return;
    }

    // Build log path: /tmp/shadow_diff_<pid>.log
    std::string log_path = "/tmp/shadow_diff_" + std::to_string(getpid()) + ".log";
    std::ofstream log(log_path);
    if (!log.is_open()) {
        std::cerr << COLOR_YELLOW << "[DIFF] Could not open log file: "
                  << log_path << COLOR_RESET << std::endl;
        return;
    }

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

                // OverlayFS whiteout — file was deleted by the package
                if (name.size() > 4 && name.substr(0, 4) == ".wh.") {
                    std::string deleted = rel_prefix + "/" + name.substr(4);
                    log << "[-] DELETED  " << deleted << "\n";
                    del_count++;
                    continue;
                }

                struct stat st;
                if (lstat(full_path.c_str(), &st) != 0) continue;

                if (S_ISDIR(st.st_mode)) {
                    walk(full_path, rel_path);
                } else {
                    std::string size_str;
                    if (st.st_size < 1024)
                        size_str = std::to_string(st.st_size) + "B";
                    else if (st.st_size < 1024 * 1024)
                        size_str = std::to_string(st.st_size / 1024) + "KB";
                    else
                        size_str = std::to_string(st.st_size / (1024 * 1024)) + "MB";

                    log << "[+] " << rel_path << " (" << size_str << ")\n";
                    file_count++;
                }
            }
            closedir(d);
        };

    walk(upper_dir, "");
    log.close();

    // One-line summary on the terminal
    std::cout << COLOR_CYAN << "[DIFF]" << COLOR_RESET
              << " " << file_count << " file(s) written, "
              << del_count << " deleted."
              << " Full log: " << log_path << std::endl;
}

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage:" << std::endl;
        std::cerr << "  shadow analyze <package>[@<version>]        — analyze npm package" << std::endl;
        std::cerr << "  shadow analyze <path/to/package.tgz>        — analyze local npm tarball" << std::endl;
        std::cerr << "  shadow apt     <package>                    — analyze apt/deb package" << std::endl;
        std::cerr << "  shadow apt     <path/to/package.deb>        — analyze local .deb" << std::endl;
        return 1;
    }

    std::string command = argv[1];
    std::string target  = argv[2];

    // If the target is a local tarball, sandbox.cpp will copy it to /tmp
    // automatically before clone() — no rewriting needed here.
    std::string npm_target = target;

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
            "--cache=/tmp/.npm-" + std::to_string(getpid()), // unique cache per run — prevents stale cache skipping preinstall
            "--fetch-timeout=5000",
            "--force",      // force re-extract even if package appears up-to-date
            "--no-package-lock",
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

        // Write filesystem diff to log file, print one-line summary to terminal
        write_diff_log(sandbox.overlay_upper_dir);

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

    } else if (command == "apt") {
        // ── APT / .deb package analysis ────────────────────────────────────
        // Approach 1: sandbox maintainer scripts only.
        // Does NOT run the real apt install — only preinst/postinst/prerm/postrm
        // are executed inside Shadow's sandbox so the eBPF hooks observe them.
        std::cout << "=== Shadow Analyzer v1.0 ===" << std::endl;
        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                  << " Mode: apt/deb | Target: " << target << "\n" << std::endl;

        // Step 1 — Fetch the .deb and extract maintainer scripts
        AptAnalyzer apt;
        if (!apt.fetch(target)) {
            std::cerr << COLOR_RED
                      << "[Shadow] Failed to fetch package. Aborting."
                      << COLOR_RESET << std::endl;
            return 1;
        }

        auto scripts = apt.extract_scripts();

        if (scripts.empty()) {
            std::cout << COLOR_GREEN
                      << "[RESULT] CLEAN — No maintainer scripts found. Nothing to sandbox."
                      << COLOR_RESET << std::endl;
            apt.cleanup();
            return 0;
        }

        // Step 2 — Load eBPF probes once, reused across all scripts
        Observer kernel_observer;
        if (!kernel_observer.start()) {
            std::cerr << "Failed to initialize kernel security module. Aborting." << std::endl;
            apt.cleanup();
            return 1;
        }

        // Step 3 — Run each maintainer script inside the sandbox
        // Scripts are invoked as: sh <script> configure (mimicking dpkg behaviour)
        int overall_status = 0;
        for (const auto& script_path : scripts) {
            if (kernel_observer.threat_detected) break; // stop on first hit

            std::string script_name = script_path.substr(script_path.find_last_of('/') + 1);
            std::cout << "\n" << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                      << " Sandboxing maintainer script: " << script_name << std::endl;

            // Stage the script into /tmp so the sandbox can find it after pivot_root
            std::string staged = "/tmp/shadow_apt_script_" + script_name;
            {
                std::ifstream src(script_path, std::ios::binary);
                std::ofstream dst(staged, std::ios::binary);
                if (src && dst) {
                    dst << src.rdbuf();
                    chmod(staged.c_str(), 0755);
                }
            }

            Sandbox sandbox;
            // Pass staged path as argv[2] so construct_prison() can stage it.
            // Then run: sh /tmp/shadow_apt_script_<name> configure
            std::vector<std::string> sh_args = {
                staged,
                "configure"
            };

            int status = sandbox.run("sh", sh_args,
                [&kernel_observer](pid_t child_pid) {
                    kernel_observer.register_sandbox_pid(child_pid);
                });

            if (status == 124) overall_status = 124;

            unlink(staged.c_str());
        }

        // Step 4 — Drain ring buffer and report
        std::cout << "\n[Shadow] Sweeping ring buffer for final events..." << std::endl;
        sleep(2);
        kernel_observer.stop();

        std::cout << "\n[Shadow] ══════════════ ANALYSIS COMPLETE ══════════════\n";
        std::cout << COLOR_CYAN << "[APT]" << COLOR_RESET
                  << " Package: " << apt.package_name
                  << " " << apt.package_version << std::endl;

        if (overall_status == 124) {
            std::cout << COLOR_YELLOW
                      << "[RESULT] TIMEOUT — Maintainer script stalled. Requires manual review."
                      << COLOR_RESET << std::endl;
        } else if (kernel_observer.threat_detected) {
            std::cout << COLOR_RED
                      << "[RESULT] MALICIOUS — "
                      << kernel_observer.threat_description
                      << "\n         DO NOT INSTALL THIS PACKAGE."
                      << COLOR_RESET << std::endl;
        } else {
            std::cout << COLOR_GREEN
                      << "[RESULT] CLEAN — No threats detected in maintainer scripts."
                      << COLOR_RESET << std::endl;
        }

        apt.cleanup();

    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
