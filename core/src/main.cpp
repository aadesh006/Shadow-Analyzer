#include <iostream>
#include <string>
#include <vector>
#include "../include/sandbox.h"
#include "../include/parser.h"
#include "../include/observer.h"

//ANSI Terminal Colors
const std::string COLOR_RESET  = "\033[0m";
const std::string COLOR_CYAN   = "\033[1;36m";

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: shadow analyze <package>@<version>" << std::endl;
        return 1;
    }

    std::string command = argv[1];
    std::string target = argv[2];

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
            target,
            "--ignore-scripts=false",
            "--no-audit", 
            "--no-fund",
            "--cache=/tmp/.npm",
            //"--loglevel=silly",
            //"--no-progress",
            "--fetch-timeout=5000"
        };
        
        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET << " Launching " << pkg_manager << " inside sandbox..." << std::endl;
        sandbox.run(pkg_manager, args);

        std::cout << COLOR_CYAN << "[Shadow]" << COLOR_RESET << " Sandbox execution completed." << std::endl;

        kernel_observer.stop();

    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
