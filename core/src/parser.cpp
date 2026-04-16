#include "../include/parser.h"
#include <iostream>
#include <fstream>
#include <regex>

bool Parser::analyzeLog(const std::string& logFilePath) {
    std::ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        std::cerr << "[Parser] Error: Could not open trace log: " << logFilePath << std::endl;
        return false;
    }

    std::string line;
    int riskScore = 0;
    int lineNum = 0;

    std::cout << "\n[Shadow] --- Starting Heuristic Analysis ---" << std::endl;

    while (std::getline(logFile, line)) {
        lineNum++;

        if (checkExecutionHeuristic(line)) {
            riskScore += 50;
        }
        if (checkFileHeuristic(line)) {
            riskScore += 100; //Immediate Fail
        }
        if (checkNetworkHeuristic(line)) {
            
        }
    }

    logFile.close();

    std::cout << "[Shadow] Analysis complete. Processed " << lineNum << " system calls." << std::endl;

    if (riskScore >= 100) {
        std::cout << "\n[RESULT] ❌ CRITICAL RISK DETECTED. INSTALLATION BLOCKED.\n" << std::endl;
        return false;
    } else if (riskScore > 0) {
        std::cout << "\n[RESULT] ⚠️ HIGH RISK. SUSPICIOUS BEHAVIOR FOUND.\n" << std::endl;
        return false;
    }

    std::cout << "\n[RESULT] ✅ Package Behavior Clean.\n" << std::endl;
    return true;
}

bool Parser::checkExecutionHeuristic(const std::string& line) {
    // Look for processes spawning a shell or a downloader
    if (line.find("execve(") != std::string::npos) {
        if (line.find("\"/bin/sh\"") != std::string::npos || 
            line.find("\"curl\"") != std::string::npos || 
            line.find("\"wget\"") != std::string::npos) {
            std::cout << "  [ALERT] Suspicious shell execution detected: " << line << std::endl;
            return true;
        }
    }
    return false;
}

bool Parser::checkFileHeuristic(const std::string& line) {
    // Look for attempts to read sensitive system files or environment variables
    if (line.find("openat(") != std::string::npos) {
        if (line.find(".ssh") != std::string::npos || 
            line.find("environ") != std::string::npos ||
            line.find("/etc/shadow") != std::string::npos) {
            std::cout << "  [CRITICAL] Credential harvesting attempt: " << line << std::endl;
            return true;
        }
    }
    return false;
}

bool Parser::checkNetworkHeuristic(const std::string& line) {
    // strace network connects often look like: connect(..., {sa_family=AF_INET, ... sin_addr=inet_addr("X.X.X.X")
    if (line.find("connect(") != std::string::npos && line.find("AF_INET") != std::string::npos) {
        // Extract the IP address using a basic Regex
        std::regex ipRegex("inet_addr\\(\"([0-9\\.]+)\"\\)");
        std::smatch match;
        if (std::regex_search(line, match, ipRegex)) {
            std::cout << "  [INFO] Outbound network connection to IP: " << match[1] << std::endl;
            return true;
        }
    }
    return false;
}