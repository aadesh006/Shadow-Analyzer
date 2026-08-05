#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include "../include/sandbox.h"
#include "../include/observer.h"

//ANSI Terminal Colors
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: shadow analyze <package>@<version>" << std::endl;
        return 1;
    }

    std::string command = argv[1];
    std::string target = argv[2];

std::string npm_target = target;
if (!target.empty() && target[0] == '/') {
    std::string filename = target.substr(target.find_last_of('/') + 1);
    // Only rewrite if it looks like a tarball
    if (filename.find(".tgz") != std::string::npos ||
        filename.find(".tar") != std::string::npos) {
        npm_target = "/tmp/" + filename;
    }
}

    if (command == "analyze") {
        std::cout << "=== Shadow Analyzer v1.0 ===" << std::endl;
        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET << " Target: " << target << "\n" << std::endl;
        
        //Inject the eBPF Probe into the Kernel
        Observer kernel_observer;
        if (!kernel_observer.start()) {
            std::cerr << "Failed to initialize kernel security module. Aborting." << std::endl;
            return 1;
        }

        Sandbox sandbox;
        std::string pkg_manager = "npm";
        
        std::vector<std::string> args = {
            "install", 
            npm_target,
            "--ignore-scripts=false",
            "--no-audit", 
            "--no-fund",
            "--cache=/tmp/.npm",
            //"--loglevel=silly",
            //"--no-progress",
            "--fetch-timeout=5000",
            //"--loglevel=warn"
        };
        
        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET << " Launching " << pkg_manager << " inside sandbox..." << std::endl;
        
        // std::cout << "[Shadow] Invoking Behavioral Parser..." << std::endl;
        // Parser parser;
        // parser.analyzeLog("shadow_trace.log");
        int sandbox_status = sandbox.run(pkg_manager, args,
            [&kernel_observer](pid_t child_pid) {
                kernel_observer.register_sandbox_pid(child_pid);
            });

        std::cout << "[Shadow] Sweeping ring buffer for final logs..." << std::endl;
        sleep(2); 

        kernel_observer.stop(); 

        std::cout << "\n[Shadow] ══════════════ ANALYSIS COMPLETE ══════════════\n";

    if (sandbox_status == 124) {
            std::cout << COLOR_YELLOW
                      << "[RESULT] TIMEOUT — Package stalled the sandbox. Requires manual review."
                      << COLOR_RESET << std::endl;
        } 
        else if (kernel_observer.threat_detected) {
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