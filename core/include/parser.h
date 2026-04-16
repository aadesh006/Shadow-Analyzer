#pragma once

#include <string>
#include <vector>

class Parser {
public:
    bool analyzeLog(const std::string& logFilePath);

private:
    bool checkNetworkHeuristic(const std::string& line);
    bool checkFileHeuristic(const std::string& line);
    bool checkExecutionHeuristic(const std::string& line);
};