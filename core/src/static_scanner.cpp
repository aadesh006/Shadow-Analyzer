#include "../include/static_scanner.h"
#include <iostream>
#include <fstream>
#include <sstream>

#define COLOR_CYAN    "\033[1;36m"
#define COLOR_RESET   "\033[0m"

StaticScanner::StaticScanner() {}
StaticScanner::~StaticScanner() {}

StaticScanResult StaticScanner::scan_node_modules(const std::string& overlay_upper_dir) {
    StaticScanResult result;
    
    if (overlay_upper_dir.empty()) {
        return result;
    }
    
    std::cout << COLOR_CYAN << "[STATIC]" << COLOR_RESET
              << " Post-install static scan temporarily disabled (fixing segfault)" << std::endl;
    
    // Return empty result for now
    result.files_scanned = 0;
    result.has_findings = false;
    
    return result;
}

// Stub implementations to satisfy linker
bool StaticScanner::scan_js_file(const std::string& file_path, StaticScanResult& result) { return false; }
bool StaticScanner::scan_py_file(const std::string& file_path, StaticScanResult& result) { return false; }
bool StaticScanner::detect_eval_base64(const std::string& content) { return false; }
bool StaticScanner::detect_obfuscated_code(const std::string& content) { return false; }
bool StaticScanner::detect_large_base64(const std::string& content) { return false; }
bool StaticScanner::detect_suspicious_requires(const std::string& content) { return false; }
bool StaticScanner::detect_credential_patterns(const std::string& content) { return false; }
bool StaticScanner::detect_string_concatenation_obfuscation(const std::string& content) { return false; }
bool StaticScanner::detect_function_constructor_eval(const std::string& content) { return false; }
bool StaticScanner::detect_encrypted_strings(const std::string& content) { return false; }
bool StaticScanner::detect_anti_analysis_patterns(const std::string& content) { return false; }
bool StaticScanner::detect_environment_fingerprinting(const std::string& content) { return false; }
bool StaticScanner::is_scannable_file(const std::string& path) { return false; }
std::string StaticScanner::read_file_content(const std::string& path) { return ""; }