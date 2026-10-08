#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <functional>
#include <thread>
#include <chrono>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/sandbox.h"
#include "../include/observer.h"
#include "../include/apt_analyzer.h"
#include "../include/static_scanner.h"
#include "../include/shadow_watch.h"
#include "../include/shadow_watch.h"

// ANSI Terminal Colors
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_BOLD    "\033[1m"

// ---------------------------------------------------------------------------
// DiffResult
//
// Returned by analyze_diff(). Carries both the full file counts and any
// suspicious findings that should influence the verdict.
// ---------------------------------------------------------------------------
struct DiffResult {
    int  file_count      = 0;
    int  del_count       = 0;
    bool has_findings    = false;  // true if any suspicious write was found
    std::string log_path;          // path to the full diff log file

    // Specific suspicious findings — each is a human-readable description
    std::vector<std::string> findings;
};

// ---------------------------------------------------------------------------
// analyze_diff()
//
// Walks the OverlayFS upper directory. For every file written by the package:
//   1. Writes a full log to /tmp/shadow_diff_<pid>.log (if verbose)
//   2. Actively flags suspicious writes:
//        - Files written OUTSIDE sandbox_pkg/node_modules/ or sandbox_pkg/.npm
//          (packages should only write inside node_modules)
//        - Executable files written anywhere
//        - Writes to .git/hooks/ (hook injection)
//        - Writes to shell rc files (~/.bashrc, ~/.zshrc, ~/.profile)
//        - Writes to system paths (/etc/, /usr/, /bin/, /sbin/)
//
// Returns a DiffResult. If upper_dir is empty (OverlayFS not available),
// returns an empty result and prints a warning.
// ---------------------------------------------------------------------------
static DiffResult analyze_diff(const std::string& upper_dir, bool verbose = false) {
    DiffResult result;

    if (upper_dir.empty()) {
        if (verbose) {
            std::cout << COLOR_YELLOW
                      << "[DIFF] OverlayFS not available — filesystem diff skipped."
                      << COLOR_RESET << std::endl;
        }
        return result;
    }

    // Only create log file in verbose mode
    std::ofstream log;
    if (verbose) {
        result.log_path = "/tmp/shadow_diff_" + std::to_string(getpid()) + ".log";
        log.open(result.log_path);
        if (log.is_open()) {
            log << "# Shadow Filesystem Delta\n";
            log << "# Format: [+] created/modified  [-] deleted  [!] suspicious\n\n";
        }
    }

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
                    if (verbose && log.is_open()) {
                        log << "[-] DELETED  " << deleted << "\n";
                    }
                    result.del_count++;
                    continue;
                }

                struct stat st;
                if (lstat(full_path.c_str(), &st) != 0) continue;

                if (S_ISDIR(st.st_mode)) {
                    walk(full_path, rel_path);
                    continue;
                }

                // Format size (only if verbose)
                std::string size_str;
                if (verbose) {
                    if (st.st_size < 1024)
                        size_str = std::to_string(st.st_size) + "B";
                    else if (st.st_size < 1024 * 1024)
                        size_str = std::to_string(st.st_size / 1024) + "KB";
                    else
                        size_str = std::to_string(st.st_size / (1024 * 1024)) + "MB";
                    
                    if (log.is_open()) {
                        log << "[+] " << rel_path << " (" << size_str << ")";
                    }
                }
                result.file_count++;

                // 1. Executable bit set on a written file
                bool is_executable = (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));
                if (is_executable) {
                    std::string finding = "Executable written: " + rel_path;
                    result.findings.push_back(finding);
                    result.has_findings = true;
                    if (verbose && log.is_open()) {
                        log << "  [!] EXECUTABLE";
                    }
                }

                // 2. Write outside sandbox_pkg/node_modules and sandbox_pkg/.npm
                //    (npm cache and node_modules are the only expected write targets)
                bool in_node_modules = (rel_path.find("/sandbox_pkg/node_modules") != std::string::npos);
                bool in_npm_cache    = (rel_path.find("/sandbox_pkg/.npm") != std::string::npos ||
                                        rel_path.find("/.npm") != std::string::npos);
                bool in_pkg_json     = (rel_path.find("/sandbox_pkg/package") != std::string::npos);

                if (!in_node_modules && !in_npm_cache && !in_pkg_json) {
                    std::string finding = "Write outside node_modules: " + rel_path;
                    result.findings.push_back(finding);
                    result.has_findings = true;
                    if (verbose && log.is_open()) {
                        log << "  [!] OUTSIDE_NODE_MODULES";
                    }
                }

                // 3. Git hook injection
                if (rel_path.find("/.git/hooks/") != std::string::npos) {
                    std::string finding = "Git hook written: " + rel_path;
                    result.findings.push_back(finding);
                    result.has_findings = true;
                    if (verbose && log.is_open()) {
                        log << "  [!] GIT_HOOK_INJECTION";
                    }
                }

                // 4. Shell rc / profile persistence
                if (rel_path.find("/.bashrc")  != std::string::npos ||
                    rel_path.find("/.zshrc")   != std::string::npos ||
                    rel_path.find("/.profile")  != std::string::npos ||
                    rel_path.find("/.bash_profile") != std::string::npos) {
                    std::string finding = "Shell profile modified: " + rel_path;
                    result.findings.push_back(finding);
                    result.has_findings = true;
                    if (verbose && log.is_open()) {
                        log << "  [!] SHELL_PERSISTENCE";
                    }
                }

                // 5. System path write (shouldn't be possible inside sandbox
                //    but flag it if it somehow appears in the overlay)
                if (rel_path.find("/etc/")  == 0 ||
                    rel_path.find("/usr/")  == 0 ||
                    rel_path.find("/bin/")  == 0 ||
                    rel_path.find("/sbin/") == 0) {
                    std::string finding = "System path write: " + rel_path;
                    result.findings.push_back(finding);
                    result.has_findings = true;
                    if (verbose && log.is_open()) {
                        log << "  [!] SYSTEM_PATH_WRITE";
                    }
                }

                if (verbose && log.is_open()) {
                    log << "\n";
                }
            }
            closedir(d);
        };

    walk(upper_dir, "");
    if (verbose && log.is_open()) {
        log.close();
    }

    // Terminal summary - always show but cleaner in normal mode
    if (verbose) {
        std::cout << COLOR_CYAN << "[DIFF]" << COLOR_RESET
                  << " " << result.file_count << " file(s) written, "
                  << result.del_count << " deleted.";

        if (result.has_findings) {
            std::cout << " " << COLOR_YELLOW
                      << result.findings.size() << " suspicious finding(s)."
                      << COLOR_RESET;
        }

        if (!result.log_path.empty()) {
            std::cout << " Full log: " << result.log_path;
        }
        std::cout << std::endl;
    }

    // Always print suspicious findings to terminal (even in quiet mode)
    if (result.has_findings) {
        for (const auto& f : result.findings) {
            std::cout << "  " << COLOR_YELLOW << "[DIFF]" << COLOR_RESET
                      << " " << f << std::endl;
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// print_verdict()
//
// Unified verdict printer used by all commands (analyze, apt, pip).
// Verdict priority: TIMEOUT > MALICIOUS > SUSPICIOUS (static) > 
//                   SUSPICIOUS (diff) > SUSPICIOUS (network) > CLEAN
// ---------------------------------------------------------------------------
static void print_verdict(int sandbox_status,
                           const Observer& obs,
                           const DiffResult& diff,
                           const StaticScanResult& static_scan = {},
                           bool verbose = false) {
    std::cout << "\n[Shadow] ══════════════ ANALYSIS COMPLETE ══════════════\n";

    if (sandbox_status == 124) {
        std::cout << COLOR_YELLOW
                  << "[RESULT] TIMEOUT — Package stalled the sandbox. Requires manual review."
                  << COLOR_RESET << std::endl;
    } else if (obs.threat_detected) {
        std::cout << COLOR_RED
                  << "[RESULT] MALICIOUS — "
                  << obs.threat_description
                  << "\n         DO NOT INSTALL THIS PACKAGE."
                  << COLOR_RESET << std::endl;
    } else if (static_scan.has_findings) {
        std::cout << COLOR_YELLOW
                  << "[RESULT] SUSPICIOUS — Static analysis flagged "
                  << static_scan.findings.size() << " dormant threat(s).\n";
        if (verbose) {
            for (const auto& f : static_scan.findings) {
                std::cout << "           • " << f << "\n";
            }
        }
        std::cout << "         Package may contain staged payloads or obfuscated malware."
                  << (verbose ? "" : " Use --verbose for details.")
                  << COLOR_RESET << std::endl;
    } else if (diff.has_findings) {
        std::cout << COLOR_YELLOW
                  << "[RESULT] SUSPICIOUS — Filesystem analysis flagged "
                  << diff.findings.size() << " issue(s).\n";
        if (verbose) {
            for (const auto& f : diff.findings) {
                std::cout << "           • " << f << "\n";
            }
        }
        std::cout << "         Manual review recommended before installing."
                  << (verbose ? "" : " Use --verbose for details.")
                  << COLOR_RESET << std::endl;
    } else if (obs.suspicious_connections > 0) {
        std::cout << COLOR_YELLOW
                  << "[RESULT] SUSPICIOUS — "
                  << obs.suspicious_connections
                  << " non-CDN outbound connection(s) detected."
                  << "\n         Manual review recommended before installing."
                  << COLOR_RESET << std::endl;
    } else {
        std::cout << COLOR_GREEN
                  << "[RESULT] CLEAN — No threats detected."
                  << COLOR_RESET;
        
        // Show static scan summary for clean packages
        if (static_scan.files_scanned > 0) {
            std::cout << " Post-install scan: " << static_scan.files_scanned << " files analyzed.";
        }
        
        std::cout << std::endl;
    }
}

// Global verbose flag
bool g_verbose_mode = false;

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:" << std::endl;
        std::cerr << "  shadow analyze <package>[@<version>] [--verbose]  — analyze npm package" << std::endl;
        std::cerr << "  shadow analyze <path/to/package.tgz> [--verbose]  — analyze local npm tarball" << std::endl;
        std::cerr << "  shadow apt     <package> [--verbose]             — analyze apt/deb package" << std::endl;
        std::cerr << "  shadow apt     <path/to/package.deb> [--verbose] — analyze local .deb" << std::endl;
        std::cerr << "  shadow pip     <package> [--verbose]             — analyze pip/PyPI package" << std::endl;
        std::cerr << "  shadow pip     <path/to/package.tar.gz> [--verbose] — analyze local Python package" << std::endl;
        std::cerr << "  shadow watch   <start|stop|status|logs>          — EDR daemon control" << std::endl;
        std::cerr << std::endl;
        std::cerr << "Options:" << std::endl;
        std::cerr << "  --verbose    Show detailed analysis logs" << std::endl;
        return 1;
    }

    std::string command = argv[1];
    
    // Check for verbose flag in any position
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--verbose") {
            g_verbose_mode = true;
            break;
        }
    }
    
    if (command == "watch") {
        // ── shadow watch daemon control ────────────────────────────────────────
        if (argc < 3) {
            std::cerr << "Usage: shadow watch <start|stop|status|logs>" << std::endl;
            return 1;
        }
        
        std::string watch_command = argv[2];
        
        if (watch_command == "start") {
            std::cout << "=== Shadow Watch EDR Daemon ===" << std::endl;
            
            ShadowWatchDaemon daemon;
            if (!daemon.start()) {
                return 1;
            }
            
            // Run daemon until interrupted
            std::cout << COLOR_CYAN << "[WATCH]" << COLOR_RESET 
                      << " Press Ctrl+C to stop daemon..." << std::endl;
            
            // Simple signal handling for demo
            bool running = true;
            signal(SIGINT, [](int) { 
                std::cout << "\n" << COLOR_CYAN << "[WATCH]" << COLOR_RESET 
                          << " Received interrupt signal..." << std::endl;
                exit(0);
            });
            
            // Keep daemon running
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            
        } else if (watch_command == "status") {
            std::cout << "=== Shadow Watch Status ===" << std::endl;
            std::cout << COLOR_YELLOW << "[WATCH] Status command not yet implemented" 
                      << COLOR_RESET << std::endl;
            std::cout << "Future: Show daemon status, recent events, statistics" << std::endl;
            
        } else if (watch_command == "logs") {
            std::cout << "=== Shadow Watch Logs ===" << std::endl;
            std::cout << COLOR_YELLOW << "[WATCH] Logs command not yet implemented" 
                      << COLOR_RESET << std::endl;
            std::cout << "Future: Show recent log entries, filter by package/type" << std::endl;
            
        } else if (watch_command == "stop") {
            std::cout << "=== Shadow Watch Stop ===" << std::endl;
            std::cout << COLOR_YELLOW << "[WATCH] Stop command not yet implemented" 
                      << COLOR_RESET << std::endl;
            std::cout << "Future: Signal running daemon to stop gracefully" << std::endl;
            
        } else {
            std::cerr << "Unknown watch command: " << watch_command << std::endl;
            std::cerr << "Available: start, stop, status, logs" << std::endl;
            return 1;
        }
        
        return 0;
    }
    
    // Require target for non-watch commands
    if (argc < 3) {
        std::cerr << "Usage:" << std::endl;
        std::cerr << "  shadow analyze <package>[@<version>]        — analyze npm package" << std::endl;
        std::cerr << "  shadow analyze <path/to/package.tgz>        — analyze local npm tarball" << std::endl;
        std::cerr << "  shadow apt     <package>                    — analyze apt/deb package" << std::endl;
        std::cerr << "  shadow apt     <path/to/package.deb>        — analyze local .deb" << std::endl;
        std::cerr << "  shadow pip     <package>                    — analyze pip/PyPI package" << std::endl;
        std::cerr << "  shadow pip     <path/to/package.tar.gz>     — analyze local Python package" << std::endl;
        std::cerr << "  shadow watch   <start|stop|status|logs>     — EDR daemon control" << std::endl;
        return 1;
    }

    std::string target  = argv[2];
    std::string npm_target = target;

    if (command == "analyze") {
        std::cout << "=== Shadow Analyzer v1.0 ===" << std::endl;
        if (g_verbose_mode) {
            std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                      << " Target: " << target << "\n" << std::endl;
        }

        Observer kernel_observer;
        if (!kernel_observer.start()) {  
            std::cerr << "Failed to initialize kernel security module. Aborting." << std::endl;
            return 1;
        }

        Sandbox sandbox;

        std::vector<std::string> npm_args = {
            "install",
            npm_target,
            "--ignore-scripts=false",
            "--no-audit",
            "--no-fund",
            "--cache=/tmp/.npm-" + std::to_string(getpid()),
            "--fetch-timeout=5000",
            "--force",
            "--no-package-lock",
        };

        if (g_verbose_mode) {
            std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                      << " Launching npm inside sandbox..." << std::endl;
        }

        int sandbox_status = sandbox.run("npm", npm_args,
            [&kernel_observer](pid_t child_pid) {
                kernel_observer.register_sandbox_pid(child_pid);
            });  

        if (g_verbose_mode) {
            std::cout << "[Shadow] Sweeping ring buffer for final events..." << std::endl;
        }
        sleep(2);
        kernel_observer.stop();

        DiffResult diff = analyze_diff(sandbox.overlay_upper_dir, g_verbose_mode);

        // ── Post-install static scan ────────────────────────────────────────────
        // Run static analysis on installed packages to detect dormant threats
        // that behaved cleanly during runtime but contain staged payloads
        StaticScanResult static_scan;
        
        // Only run static scan if no runtime threats detected and overlay available
        if (!kernel_observer.threat_detected && !sandbox.overlay_upper_dir.empty()) {
            StaticScanner scanner;
            static_scan = scanner.scan_node_modules(sandbox.overlay_upper_dir);
        }

        print_verdict(sandbox_status, kernel_observer, diff, static_scan, g_verbose_mode);

    } else if (command == "apt") {
        std::cout << "=== Shadow Analyzer v1.0 ===" << std::endl;
        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                  << " Mode: apt/deb | Target: " << target << "\n" << std::endl;

        AptAnalyzer apt;
        if (!apt.fetch(target)) {
            std::cerr << COLOR_RED << "[Shadow] Failed to fetch package. Aborting."
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

        Observer kernel_observer;
        if (!kernel_observer.start()) {
            std::cerr << "Failed to initialize kernel security module. Aborting." << std::endl;
            apt.cleanup();
            return 1;
        }

        int overall_status = 0;
        for (const auto& script_path : scripts) {
            if (kernel_observer.threat_detected) break;

            std::string script_name = script_path.substr(script_path.find_last_of('/') + 1);
            std::cout << "\n" << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                      << " Sandboxing maintainer script: " << script_name << std::endl;

            std::string staged = "/tmp/shadow_apt_script_" + script_name;
            {
                std::ifstream src(script_path, std::ios::binary);
                std::ofstream dst(staged, std::ios::binary);
                if (src && dst) { dst << src.rdbuf(); chmod(staged.c_str(), 0755); }
            }

            Sandbox sandbox;
            std::vector<std::string> sh_args = {
                "sh",
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

        std::cout << "\n[Shadow] Sweeping ring buffer for final events..." << std::endl;
        sleep(2);
        kernel_observer.stop();

        std::cout << COLOR_CYAN << "[APT]" << COLOR_RESET
                  << " Package: " << apt.package_name
                  << " " << apt.package_version << std::endl;

        // apt runs scripts without OverlayFS — pass empty DiffResult and StaticScanResult
        DiffResult empty_diff;
        StaticScanResult empty_static;
        print_verdict(overall_status, kernel_observer, empty_diff, empty_static, g_verbose_mode);

        apt.cleanup();

    } else if (command == "pip") {
        // ── pip / PyPI package analysis ────────────────────────────────────
        // Reuses the same sandbox + eBPF architecture as npm. Python packages
        // execute setup.py hooks during install — same threat model as npm scripts.
        // We run `pip install` inside the sandbox and observe behavior.
        std::cout << "=== Shadow Analyzer v1.0 ===" << std::endl;
        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                  << " Mode: pip/PyPI | Target: " << target << "\n" << std::endl;

        Observer kernel_observer;
        if (!kernel_observer.start()) {
            std::cerr << "Failed to initialize kernel security module. Aborting." << std::endl;
            return 1;
        }

        Sandbox sandbox;

        // Detect local Python package files vs PyPI registry packages
        std::string pip_target = target;
        if (target.size() > 1 && target[0] == '/' &&
            (target.find(".tar.gz") != std::string::npos ||
             target.find(".whl") != std::string::npos ||
             target.find(".zip") != std::string::npos)) {
            // Local package — sandbox.cpp will copy it to /tmp automatically
            std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                      << " Local Python package detected." << std::endl;
        }

        // Try multiple pip invocation methods for maximum compatibility
        std::vector<std::vector<std::string>> pip_variants = {
            {"pip3", "install", pip_target, "--no-deps", "--force-reinstall", "--no-cache-dir"},
            {"python3", "-m", "pip", "install", pip_target, "--no-deps", "--force-reinstall", "--no-cache-dir"},
            {"pip", "install", pip_target, "--no-deps", "--force-reinstall", "--no-cache-dir"}
        };

        std::string pip_cmd;
        std::vector<std::string> pip_args;
        
        // Use the first variant as default (can be enhanced to detect available pip)
        pip_cmd = pip_variants[1][0]; // python3
        pip_args = {pip_variants[1].begin() + 1, pip_variants[1].end()};

        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET
                  << " Launching " << pip_cmd << " inside sandbox..." << std::endl;

        int sandbox_status = sandbox.run(pip_cmd, pip_args,
            [&kernel_observer](pid_t child_pid) {
                kernel_observer.register_sandbox_pid(child_pid);
            });

        std::cout << "[Shadow] Sweeping ring buffer for final events..." << std::endl;
        sleep(2);
        kernel_observer.stop();

        DiffResult diff = analyze_diff(sandbox.overlay_upper_dir, g_verbose_mode);

        // ── Post-install static scan ────────────────────────────────────────────
        // Run static analysis on installed Python packages
        StaticScanResult static_scan;
        
        if (!kernel_observer.threat_detected && !sandbox.overlay_upper_dir.empty()) {
            StaticScanner scanner;
            static_scan = scanner.scan_node_modules(sandbox.overlay_upper_dir); // Works for Python too
        }

        std::cout << COLOR_CYAN << "[PIP]" << COLOR_RESET
                  << " Package: " << target << std::endl;

        print_verdict(sandbox_status, kernel_observer, diff, static_scan, g_verbose_mode);

    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
