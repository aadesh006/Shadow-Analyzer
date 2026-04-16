#include "../include/parser.h"
#include <iostream>
#include <fstream>
#include <regex>

//ANSI Terminal Colors
const std::string COLOR_RESET  = "\033[0m";
const std::string COLOR_RED    = "\033[1;31m"; // 1; makes it bold
const std::string COLOR_GREEN  = "\033[1;32m";
const std::string COLOR_YELLOW = "\033[1;33m";
const std::string COLOR_CYAN   = "\033[1;36m";

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
        std::cout << "\n" << COLOR_RED << "[RESULT] CRITICAL RISK DETECTED. INSTALLATION BLOCKED." << COLOR_RESET << "\n" << std::endl;
        return false;
    } else if (riskScore > 0) {
        std::cout << "\n" << COLOR_YELLOW << "[RESULT] HIGH RISK. SUSPICIOUS BEHAVIOR FOUND." << COLOR_RESET << "\n" << std::endl;
        return false;
    }

    std::cout << "\n" << COLOR_GREEN << "[RESULT] Package Behavior Clean." << COLOR_RESET << "\n" << std::endl;
    return true;
}

bool Parser::checkExecutionHeuristic(const std::string& line) {
    // Look for processes spawning a shell or a downloader
    if (line.find("execve(") != std::string::npos) {
        if (line.find("\"/bin/sh\"") != std::string::npos || 
            line.find("\"curl\"") != std::string::npos || 
            line.find("\"wget\"") != std::string::npos) {
            std::cout << "  " << COLOR_YELLOW << "[ALERT]" << COLOR_RESET << " Suspicious shell execution detected: " << line << std::endl;
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
            std::cout << "  " << COLOR_RED << "[CRITICAL]" << COLOR_RESET << " Credential harvesting attempt: " << line << std::endl;
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
            std::cout << "  " << COLOR_CYAN << "[INFO]" << COLOR_RESET << " Outbound network connection to IP: " << match[1] << std::endl;
            return true;
        }
    }
    return false;
}