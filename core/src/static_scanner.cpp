#include "../include/static_scanner.h"
#include "../include/common.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <dirent.h>
#include <sys/stat.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"

StaticScanner::StaticScanner() {}
StaticScanner::~StaticScanner() {}

// ---------------------------------------------------------------------------
// scan_node_modules()
//
// Main entry point. Recursively scans all JavaScript/TypeScript files in
// the OverlayFS upper directory (which contains node_modules/ after install).
// ---------------------------------------------------------------------------
StaticScanResult StaticScanner::scan_node_modules(const std::string& overlay_upper_dir) {
    StaticScanResult result;
    
    if (overlay_upper_dir.empty()) {
        return result; // No overlay dir means no files to scan
    }
    
    if (g_verbose_mode) {
        std::cout << COLOR_CYAN << "[STATIC]" << COLOR_RESET
                  << " Scanning installed packages for dormant threats..." << std::endl;
    }
    
    // Recursively scan the overlay upper directory
    std::function<void(const std::string&)> scan_dir = [&](const std::string& dir_path) {
        DIR* d = opendir(dir_path.c_str());
        if (!d) return;
        
        struct dirent* ent;
        while ((ent = readdir(d)) != nullptr) {
            std::string name(ent->d_name);
            if (name == "." || name == "..") continue;
            
            std::string full_path = dir_path + "/" + name;
            struct stat st;
            if (lstat(full_path.c_str(), &st) != 0) continue;
            
            if (S_ISDIR(st.st_mode)) {
                scan_dir(full_path);
            } else if (is_scannable_file(full_path)) {
                result.files_scanned++;
                
                // Determine file type and scan accordingly
                if (full_path.find(".py") != std::string::npos) {
                    scan_py_file(full_path, result);
                } else {
                    scan_js_file(full_path, result); // JS/TS/JSON
                }
            }
        }
        closedir(d);
    };
    
    scan_dir(overlay_upper_dir);
    
    if (g_verbose_mode) {
        std::cout << COLOR_CYAN << "[STATIC]" << COLOR_RESET
                  << " Scanned " << result.files_scanned << " files";
        
        if (result.has_findings) {
            std::cout << ", found " << result.findings.size() << " suspicious pattern(s).";
        } else {
            std::cout << ", no suspicious patterns detected.";
        }
        std::cout << std::endl;
    }
    
    return result;
}

// ---------------------------------------------------------------------------
// scan_js_file()
//
// Scan a single JavaScript/TypeScript file for malicious patterns.
// ---------------------------------------------------------------------------
bool StaticScanner::scan_js_file(const std::string& file_path, StaticScanResult& result) {
    std::string content = read_file_content(file_path);
    if (content.empty()) return false;
    
    bool found_threat = false;
    
    // 1. eval(Buffer.from(..., 'base64')) - common obfuscation technique
    if (detect_eval_base64(content)) {
        result.findings.push_back("eval(Buffer.from base64) in " + file_path);
        result.eval_patterns++;
        result.has_findings = found_threat = true;
    }
    
    // 2. Heavy obfuscation (excessive unicode escapes, hex encoding)
    if (detect_obfuscated_code(content)) {
        result.findings.push_back("Obfuscated code in " + file_path);
        result.obfuscated_code++;
        result.has_findings = found_threat = true;
    }
    
    // 3. Large base64 encoded strings (>500 chars, potential encrypted payloads)
    if (detect_large_base64(content)) {
        result.findings.push_back("Large base64 payload in " + file_path);
        result.base64_payloads++;
        result.has_findings = found_threat = true;
    }
    
    // 4. Suspicious require() patterns
    if (detect_suspicious_requires(content)) {
        result.findings.push_back("Suspicious process spawn code in " + file_path);
        result.suspicious_processes++;
        result.has_findings = found_threat = true;
    }
    
    // 5. Credential access patterns
    if (detect_credential_patterns(content)) {
        result.findings.push_back("Credential access code in " + file_path);
        result.credential_access++;
        result.has_findings = found_threat = true;
    }
    
    // ── Enhanced Pattern Detection (Phase 3) ────────────────────────────────
    
    // 6. String concatenation obfuscation ("ev" + "al", split strings)
    if (detect_string_concatenation_obfuscation(content)) {
        result.findings.push_back("String concatenation obfuscation in " + file_path);
        result.string_concat_obfuscation++;
        result.has_findings = found_threat = true;
    }
    
    // 7. Function constructor eval (new Function(), constructor patterns)
    if (detect_function_constructor_eval(content)) {
        result.findings.push_back("Function constructor eval pattern in " + file_path);
        result.function_constructor_usage++;
        result.has_findings = found_threat = true;
    }
    
    // 8. Encrypted string patterns (hex, custom encoding)
    if (detect_encrypted_strings(content)) {
        result.findings.push_back("Encrypted/encoded strings in " + file_path);
        result.encrypted_payloads++;
        result.has_findings = found_threat = true;
    }
    
    // 9. Anti-analysis techniques (debugger detection, VM detection)
    if (detect_anti_analysis_patterns(content)) {
        result.findings.push_back("Anti-analysis techniques in " + file_path);
        result.anti_analysis++;
        result.has_findings = found_threat = true;
    }
    
    // 10. Environment fingerprinting (checking OS, Node version, etc.)
    if (detect_environment_fingerprinting(content)) {
        result.findings.push_back("Environment fingerprinting in " + file_path);
        result.environment_checks++;
        result.has_findings = found_threat = true;
    }
    
    return found_threat;
}

// ---------------------------------------------------------------------------
// scan_py_file()
//
// Scan a Python file for malicious patterns.
// ---------------------------------------------------------------------------
bool StaticScanner::scan_py_file(const std::string& file_path, StaticScanResult& result) {
    std::string content = read_file_content(file_path);
    if (content.empty()) return false;
    
    bool found_threat = false;
    
    // Python-specific patterns
    std::regex eval_b64_py(R"(eval\(\s*base64\.(b64decode|decodebytes))");
    std::regex exec_b64_py(R"(exec\(\s*base64\.(b64decode|decodebytes))");
    std::regex subprocess_py(R"(subprocess\.(run|call|Popen|check_output).*['\"][^'\"]*(?:curl|wget|nc|sh|bash))");
    
    if (std::regex_search(content, eval_b64_py) || std::regex_search(content, exec_b64_py)) {
        result.findings.push_back("eval/exec(base64.decode) in " + file_path);
        result.eval_patterns++;
        result.has_findings = found_threat = true;
    }
    
    if (std::regex_search(content, subprocess_py)) {
        result.findings.push_back("Suspicious subprocess call in " + file_path);
        result.suspicious_processes++;
        result.has_findings = found_threat = true;
    }
    
    // Check for large base64 in Python too
    if (detect_large_base64(content)) {
        result.findings.push_back("Large base64 payload in " + file_path);
        result.base64_payloads++;
        result.has_findings = found_threat = true;
    }
    
    return found_threat;
}

// ---------------------------------------------------------------------------
// Pattern Detection Functions
// ---------------------------------------------------------------------------

bool StaticScanner::detect_eval_base64(const std::string& content) {
    try {
        // Match: eval(Buffer.from('...', 'base64'))
        std::regex pattern(R"(eval\s*\(\s*Buffer\s*\.\s*from\s*\(\s*['"][^'"]*['"]\s*,\s*['"]base64['"]\s*\))");
        return std::regex_search(content, pattern);
    } catch (const std::exception& e) {
        return false;
    }
}



bool StaticScanner::detect_obfuscated_code(const std::string& content) {
    // Count unicode and hex escapes using simple string search
    int unicode_count = 0;
    int hex_count = 0;
    
    size_t pos = 0;
    while ((pos = content.find("\\u", pos)) != std::string::npos) {
        unicode_count++;
        pos += 2;
    }
    
    pos = 0;
    while ((pos = content.find("\\x", pos)) != std::string::npos) {
        hex_count++;
        pos += 2;
    }
    
    return (unicode_count > 20) || (hex_count > 50);
}

bool StaticScanner::detect_large_base64(const std::string& content) {
    // Look for long strings (potential base64 payloads)
    size_t pos = 0;
    while ((pos = content.find_first_of("\"'", pos)) != std::string::npos) {
        size_t end = content.find(content[pos], pos + 1);
        if (end != std::string::npos && (end - pos) > 500) {
            return true;
        }
        pos = (end != std::string::npos) ? end + 1 : pos + 1;
        if (pos >= content.length()) break;
    }
    return false;
}

bool StaticScanner::detect_suspicious_requires(const std::string& content) {
    bool has_child_process = (content.find("child_process") != std::string::npos);
    bool has_exec = (content.find("exec") != std::string::npos || content.find("spawn") != std::string::npos);
    bool has_dangerous = (content.find("curl") != std::string::npos || 
                         content.find("wget") != std::string::npos || 
                         content.find("bash") != std::string::npos);
    return has_child_process && has_exec && has_dangerous;
}

bool StaticScanner::detect_credential_patterns(const std::string& content) {
    bool has_file_read = (content.find("readFile") != std::string::npos || content.find("fs.read") != std::string::npos);
    bool has_cred_path = (content.find("/etc/passwd") != std::string::npos ||
                         content.find(".ssh/") != std::string::npos ||
                         content.find(".aws/") != std::string::npos ||
                         content.find(".env") != std::string::npos);
    return has_file_read && has_cred_path;
}

bool StaticScanner::detect_string_concatenation_obfuscation(const std::string& content) {
    // Look for "ev" + "al" style obfuscation
    bool has_eval_concat = (content.find("\"ev\"") != std::string::npos && content.find("\"al\"") != std::string::npos) ||
                          (content.find("'ev'") != std::string::npos && content.find("'al'") != std::string::npos);
    bool has_split_join = (content.find(".split(") != std::string::npos && content.find(".join(") != std::string::npos);
    return has_eval_concat || has_split_join;
}

bool StaticScanner::detect_function_constructor_eval(const std::string& content) {
    return (content.find("new Function") != std::string::npos) ||
           (content.find(".constructor(") != std::string::npos) ||
           (content.find("globalThis['eval']") != std::string::npos);
}

bool StaticScanner::detect_encrypted_strings(const std::string& content) {
    bool has_long_string = false;
    size_t pos = 0;
    while ((pos = content.find_first_of("\"'", pos)) != std::string::npos) {
        size_t end = content.find(content[pos], pos + 1);
        if (end != std::string::npos && (end - pos) > 100) {
            has_long_string = true;
            break;
        }
        pos = (end != std::string::npos) ? end + 1 : pos + 1;
        if (pos >= content.length()) break;
    }
    
    bool has_xor = (content.find(" ^ 0x") != std::string::npos);
    bool has_decode = (content.find("decode") != std::string::npos || content.find("decrypt") != std::string::npos);
    bool has_fromCharCode = (content.find("String.fromCharCode") != std::string::npos);
    
    return has_long_string || (has_xor && has_decode) || has_fromCharCode;
}

bool StaticScanner::detect_anti_analysis_patterns(const std::string& content) {
    return (content.find("debugger") != std::string::npos) ||
           (content.find("performance.now") != std::string::npos && content.find("Date.now") != std::string::npos) ||
           (content.find("VirtualBox") != std::string::npos || content.find("VMware") != std::string::npos) ||
           (content.find("console.clear") != std::string::npos) ||
           (content.find("Error().stack") != std::string::npos);
}

bool StaticScanner::detect_environment_fingerprinting(const std::string& content) {
    int env_checks = 0;
    
    if (content.find("process.platform") != std::string::npos) env_checks++;
    if (content.find("os.platform") != std::string::npos) env_checks++;
    if (content.find("process.version") != std::string::npos) env_checks++;
    if (content.find("process.env.USER") != std::string::npos) env_checks++;
    if (content.find("process.env.USERNAME") != std::string::npos) env_checks++;
    if (content.find("os.userInfo") != std::string::npos) env_checks++;
    if (content.find("os.hostname") != std::string::npos) env_checks++;
    if (content.find("process.arch") != std::string::npos) env_checks++;
    
    return env_checks > 2;
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

bool StaticScanner::is_scannable_file(const std::string& path) {
    return (path.find(".js") != std::string::npos ||
            path.find(".ts") != std::string::npos ||
            path.find(".mjs") != std::string::npos ||
            path.find(".json") != std::string::npos ||
            path.find(".py") != std::string::npos ||
            path.find(".pyw") != std::string::npos);
}

std::string StaticScanner::read_file_content(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    if (size > 1024 * 1024) return ""; // Skip files >1MB
    
    file.seekg(0, std::ios::beg);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}
