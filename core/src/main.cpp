#include <iostream>
#include <string>
#include <vector>
#include "../include/sandbox.h"

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
        
        // spawn a shell inside the sandbox and ask it to list all processes
        std::vector<std::string> args = {
            "-c", 
            "echo '--- Inside the Sandbox ---'; ps -ef"
        };
        
        sandbox.run("sh", args);

    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}