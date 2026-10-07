#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// StaticScanResult
//
// Results from post-install static analysis of node_modules/
// ---------------------------------------------------------------------------
struct StaticScanResult {
    int files_scanned = 0;
    bool has_findings = false;
    std::vector<std::string> findings;
    
    // Categories of suspicious patterns found
    int obfuscated_code = 0;
    int base64_payloads = 0; 
    int eval_patterns = 0;
    int suspicious_processes = 0;
    int credential_access = 0;
    
    // Enhanced detection categories (Phase 3)
    int string_concat_obfuscation = 0;
    int function_constructor_usage = 0;
    int encrypted_payloads = 0;
    int anti_analysis = 0;
    int environment_checks = 0;
};

// ---------------------------------------------------------------------------
// StaticScanner
//
// Post-install static analysis for detecting staged payloads and obfuscated
// threats that behave cleanly during install but contain malicious code.
//
// Runs after a package receives CLEAN verdict from runtime analysis.
// Scans installed node_modules/ looking for:
//   - eval(Buffer.from(..., 'base64')) patterns
//   - Large base64 encoded strings  
//   - Obfuscated JavaScript (excessive unicode escapes, hex encoding)
//   - Suspicious require() calls (child_process, fs, http in unexpected contexts)
//   - Known malicious code patterns
// ---------------------------------------------------------------------------
class StaticScanner {
public:
    StaticScanner();
    ~StaticScanner();

    // Scan installed node_modules directory after npm/pip install
    // Returns findings that may indicate staged payloads
    StaticScanResult scan_node_modules(const std::string& overlay_upper_dir);

private:
    // Scan a single JavaScript/TypeScript file for suspicious patterns
    bool scan_js_file(const std::string& file_path, StaticScanResult& result);
    
    // Scan a Python file for suspicious patterns
    bool scan_py_file(const std::string& file_path, StaticScanResult& result);
    
    // Pattern detection functions
    bool detect_eval_base64(const std::string& content);
    bool detect_obfuscated_code(const std::string& content);
    bool detect_large_base64(const std::string& content);
    bool detect_suspicious_requires(const std::string& content);
    bool detect_credential_patterns(const std::string& content);
    
    // Enhanced pattern detection (Phase 3)
    bool detect_string_concatenation_obfuscation(const std::string& content);
    bool detect_function_constructor_eval(const std::string& content);
    bool detect_encrypted_strings(const std::string& content);
    bool detect_anti_analysis_patterns(const std::string& content);
    bool detect_environment_fingerprinting(const std::string& content);
    
    // Helper functions
    bool is_scannable_file(const std::string& path);
    std::string read_file_content(const std::string& path);
};