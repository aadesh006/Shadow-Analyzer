#include <iostream>
#include <string>
#include <vector>
#include "../include/sandbox.h"
#include "../include/parser.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: shadow analyze <package>@<version>" << std::endl;
        return 1;
    }

    std::string command = argv[1];
    std::string target = argv[2];

    if (command == "analyze") {
        std::cout << "=== Shadow Analyzer v1.0 ===" << std::endl;
        std::cout << "[Shadow] Target: " << target << "\n" << std::endl;
        
        Sandbox sandbox;
        
        std::string pkg_manager = "npm";
        
        // instruct npm to install the specific target package.
        std::vector<std::string> args = {
            "install", 
            target,
            "--ignore-scripts=false",
            "--no-audit",
            "--no-fund"
        };
        
        std::cout << "[Shadow] Launching " << pkg_manager << " inside sandbox..." << std::endl;
        sandbox.run(pkg_manager, args);

        std::cout << "[Shadow] Sandbox execution completed." << std::endl;

        Parser parser;
        parser.analyzeLog("shadow_trace.log");

    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}