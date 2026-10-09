#include "../include/shadow_watch.h"
#include "../include/observer.h"
#include "../include/static_scanner.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <algorithm>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"

ShadowWatchDaemon::ShadowWatchDaemon() {
    // Initialize start time
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    start_time_ = ss.str();
}

ShadowWatchDaemon::~ShadowWatchDaemon() {
    stop();
}

// ---------------------------------------------------------------------------
// start()
//
// Initialize and start the shadow watch daemon
// ---------------------------------------------------------------------------
bool ShadowWatchDaemon::start(const std::string& config_path) {
    if (running_) {
        std::cout << COLOR_YELLOW << "[WATCH] Daemon already running" << COLOR_RESET << std::endl;
        return true;
    }
    
    std::cout << COLOR_CYAN << "[WATCH]" << COLOR_RESET 
              << " Starting Shadow Watch EDR daemon..." << std::endl;
    
    // Daemonize the process
    if (!daemonize()) {
        std::cerr << COLOR_RED << "[WATCH] Failed to daemonize process" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Load configuration
    if (!load_config(config_path)) {
        // Log to syslog since we're now daemonized
        // For now, continue with defaults
    }
    
    // Initialize eBPF observer (same as sandbox but system-wide)
    observer_ = std::make_unique<Observer>();
    if (!observer_->start()) {
        return false;
    }
    
    // Create log directory
    system("mkdir -p /var/log/shadow 2>/dev/null");
    
    // Start monitoring thread
    running_ = true;
    monitor_thread_ = std::make_unique<std::thread>(&ShadowWatchDaemon::monitor_loop, this);
    
    return true;
}

// ---------------------------------------------------------------------------
// daemonize()
//
// Properly daemonize the process (fork, setsid, etc.)
// ---------------------------------------------------------------------------
bool ShadowWatchDaemon::daemonize() {
    // First fork
    pid_t pid = fork();
    if (pid < 0) {
        return false; // Fork failed
    }
    if (pid > 0) {
        // Parent process - write PID and exit
        std::ofstream pid_file("/var/run/shadow-watch.pid");
        if (pid_file.is_open()) {
            pid_file << pid << std::endl;
            pid_file.close();
        }
        exit(0); // Parent exits
    }
    
    // Child continues - create new session
    if (setsid() < 0) {
        return false;
    }
    
    // Second fork to prevent acquiring terminal
    pid = fork();
    if (pid < 0) {
        return false;
    }
    if (pid > 0) {
        exit(0); // First child exits
    }
    
    // Grandchild continues as daemon
    umask(0); // Clear umask
    
    // Change to root directory
    if (chdir("/") < 0) {
        return false;
    }
    
    // Close stdin, stdout, stderr and redirect to /dev/null
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Redirect to /dev/null
    open("/dev/null", O_RDONLY); // stdin
    open("/dev/null", O_WRONLY); // stdout  
    open("/dev/null", O_WRONLY); // stderr
    
    return true;
}

// ---------------------------------------------------------------------------
// stop()
//
// Gracefully stop the daemon
// ---------------------------------------------------------------------------
void ShadowWatchDaemon::stop() {
    if (!running_) return;
    
    std::cout << COLOR_CYAN << "[WATCH]" << COLOR_RESET 
              << " Stopping Shadow Watch daemon..." << std::endl;
    
    running_ = false;
    
    if (monitor_thread_ && monitor_thread_->joinable()) {
        monitor_thread_->join();
    }
    
    if (observer_) {
        observer_->stop();
    }
    
    std::cout << COLOR_GREEN << "[WATCH] Shadow Watch daemon stopped" 
              << COLOR_RESET << std::endl;
}

// ---------------------------------------------------------------------------
// load_config()
//
// Load daemon configuration from file
// ---------------------------------------------------------------------------
bool ShadowWatchDaemon::load_config(const std::string& config_path) {
    // Initialize with defaults
    policy_ = WatchPolicy{};
    
    // Try multiple config file locations
    std::vector<std::string> config_paths;
    if (!config_path.empty()) {
        config_paths.push_back(config_path);
    }
    config_paths.push_back("/etc/shadow-watch/config.conf");
    config_paths.push_back("/etc/shadow-watch.conf");
    config_paths.push_back("./shadow-watch.conf");
    
    std::ifstream config_file;
    std::string used_path;
    
    for (const auto& path : config_paths) {
        config_file.open(path);
        if (config_file.is_open()) {
            used_path = path;
            break;
        }
    }
    
    if (!config_file.is_open()) {
        // No config file found, use defaults
        return true;
    }
    
    std::string line;
    std::string current_section;
    int line_number = 0;
    
    while (std::getline(config_file, line)) {
        line_number++;
        
        // Remove leading/trailing whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Check for section headers [section]
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }
        
        // Parse key=value pairs
        size_t equals_pos = line.find('=');
        if (equals_pos == std::string::npos) {
            continue; // Skip invalid lines
        }
        
        std::string key = line.substr(0, equals_pos);
        std::string value = line.substr(equals_pos + 1);
        
        // Remove whitespace around key and value
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        
        // Parse based on section and key
        parse_config_option(current_section, key, value);
    }
    
    config_file.close();
    return true;
}

// ---------------------------------------------------------------------------
// parse_config_option()
//
// Parse individual configuration options
// ---------------------------------------------------------------------------
void ShadowWatchDaemon::parse_config_option(const std::string& section, 
                                           const std::string& key, 
                                           const std::string& value) {
    if (section == "monitoring") {
        if (key == "monitor_node_processes") policy_.monitor_node_processes = parse_bool(value);
        else if (key == "monitor_python_processes") policy_.monitor_python_processes = parse_bool(value);
        else if (key == "monitor_all_processes") policy_.monitor_all_processes = parse_bool(value);
        else if (key == "watch_npm") policy_.watch_npm = parse_bool(value);
        else if (key == "watch_pip") policy_.watch_pip = parse_bool(value);
        else if (key == "watch_apt") policy_.watch_apt = parse_bool(value);
        else if (key == "watch_yarn") policy_.watch_yarn = parse_bool(value);
        else if (key == "watch_pnpm") policy_.watch_pnpm = parse_bool(value);
    }
    else if (section == "response") {
        if (key == "log_events") policy_.log_events = parse_bool(value);
        else if (key == "send_alerts") policy_.send_alerts = parse_bool(value);
        else if (key == "kill_on_malicious") policy_.kill_on_malicious = parse_bool(value);
        else if (key == "suspicious_connection_threshold") policy_.suspicious_connection_threshold = std::stoi(value);
        else if (key == "credential_access_threshold") policy_.credential_access_threshold = std::stoi(value);
    }
    else if (section == "logging") {
        if (key == "log_file") policy_.log_file = value;
        else if (key == "log_level") policy_.log_level = value;
        else if (key == "max_log_size") policy_.max_log_size = value;
        else if (key == "rotate_logs") policy_.rotate_logs = parse_bool(value);
    }
    else if (section == "network") {
        if (key == "monitor_outbound_connections") policy_.monitor_outbound_connections = parse_bool(value);
        else if (key == "block_known_malicious") policy_.block_known_malicious = parse_bool(value);
        else if (key == "alert_on_suspicious") policy_.alert_on_suspicious = parse_bool(value);
    }
    else if (section == "advanced") {
        if (key == "scan_frequency") {
            // Parse values like "500ms" to milliseconds
            if (value.find("ms") != std::string::npos) {
                policy_.scan_frequency_ms = std::stoi(value.substr(0, value.find("ms")));
            } else {
                policy_.scan_frequency_ms = std::stoi(value);
            }
        }
        else if (key == "event_retention") policy_.event_retention = std::stoi(value);
        else if (key == "enable_static_scan") policy_.enable_static_scan = parse_bool(value);
    }
}

// ---------------------------------------------------------------------------
// parse_bool()
//
// Parse boolean values from config (true/false, yes/no, 1/0)
// ---------------------------------------------------------------------------
bool ShadowWatchDaemon::parse_bool(const std::string& value) {
    std::string lower_value = value;
    std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);
    
    return (lower_value == "true" || lower_value == "yes" || 
            lower_value == "1" || lower_value == "on");
}

// ---------------------------------------------------------------------------
// monitor_loop()
//
// Main monitoring thread - processes eBPF events system-wide
// ---------------------------------------------------------------------------
void ShadowWatchDaemon::monitor_loop() {
    std::cout << COLOR_CYAN << "[WATCH]" << COLOR_RESET 
              << " Starting system-wide monitoring loop..." << std::endl;
    
    while (running_) {
        // Check if Observer detected any threats
        if (observer_->threat_detected) {
            WatchEvent threat_event;
            threat_event.type = WatchEvent::MALICIOUS_CONNECTION;
            threat_event.pid = 0; // Will be filled from eBPF events
            threat_event.process_name = "unknown";
            threat_event.description = observer_->threat_description;
            threat_event.package_name = "unknown";
            
            // Generate timestamp
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
            threat_event.timestamp = ss.str();
            
            handle_event(threat_event);
            
            // Reset threat flag for next detection
            observer_->threat_detected = false;
            observer_->threat_description = "";
        }
        
        // Check for suspicious connections (non-CDN, non-malicious)
        if (observer_->suspicious_connections > 0) {
            WatchEvent suspicious_event;
            suspicious_event.type = WatchEvent::SUSPICIOUS_PROCESS;
            suspicious_event.pid = 0;
            suspicious_event.process_name = "unknown";
            suspicious_event.description = "Non-CDN outbound connection detected";
            suspicious_event.package_name = "unknown";
            
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
            suspicious_event.timestamp = ss.str();
            
            handle_event(suspicious_event);
            
            // Reset counter
            observer_->suspicious_connections = 0;
        }
        
        // Monitor for package manager processes
        detect_package_installations();
        
        // Sleep based on configured scan frequency
        std::this_thread::sleep_for(std::chrono::milliseconds(policy_.scan_frequency_ms));
    }
    
    std::cout << COLOR_CYAN << "[WATCH]" << COLOR_RESET 
              << " Monitoring loop stopped" << std::endl;
}

// ---------------------------------------------------------------------------
// handle_event()
//
// Process a security event detected by the daemon
// ---------------------------------------------------------------------------
void ShadowWatchDaemon::handle_event(const WatchEvent& event) {
    {
        std::lock_guard<std::mutex> lock(events_mutex_);
        recent_events_.push_back(event);
        
        // Keep only last 1000 events
        if (recent_events_.size() > 1000) {
            recent_events_.erase(recent_events_.begin());
        }
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_events++;
        stats_.last_event_time = event.timestamp;
        
        switch (event.type) {
            case WatchEvent::CREDENTIAL_ACCESS:
                stats_.credential_blocks++;
                break;
            case WatchEvent::MALICIOUS_CONNECTION:
                stats_.malicious_connections++;
                break;
            case WatchEvent::SUSPICIOUS_PROCESS:
                stats_.suspicious_processes++;
                break;
            default:
                break;
        }
    }
    
    // Log the event
    if (policy_.log_events) {
        log_event(event);
    }
    
    // Enforce policy
    enforce_policy(event);
    
    // Print to console for immediate visibility
    std::string type_str;
    std::string color = COLOR_YELLOW;
    
    switch (event.type) {
        case WatchEvent::CREDENTIAL_ACCESS:
            type_str = "CREDENTIAL_ACCESS";
            color = COLOR_RED;
            break;
        case WatchEvent::MALICIOUS_CONNECTION:
            type_str = "MALICIOUS_CONNECTION";
            color = COLOR_RED;
            break;
        case WatchEvent::SUSPICIOUS_PROCESS:
            type_str = "SUSPICIOUS_PROCESS";
            color = COLOR_YELLOW;
            break;
        case WatchEvent::STAGED_PAYLOAD:
            type_str = "STAGED_PAYLOAD";
            color = COLOR_MAGENTA;
            break;
        case WatchEvent::POLICY_VIOLATION:
            type_str = "POLICY_VIOLATION";
            color = COLOR_RED;
            break;
    }
    
    std::cout << color << "[WATCH-ALERT]" << COLOR_RESET
              << " " << type_str << " | PID:" << event.pid
              << " | " << event.process_name
              << " | " << event.description;
    
    if (!event.package_name.empty()) {
        std::cout << " | Package:" << event.package_name;
    }
    
    std::cout << std::endl;
}

// ---------------------------------------------------------------------------
// Support functions
// ---------------------------------------------------------------------------

std::vector<WatchEvent> ShadowWatchDaemon::get_recent_events(int limit) const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    if (recent_events_.size() <= limit) {
        return recent_events_;
    }
    
    return std::vector<WatchEvent>(
        recent_events_.end() - limit, 
        recent_events_.end()
    );
}

ShadowWatchDaemon::Stats ShadowWatchDaemon::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    Stats stats = stats_;
    
    // Calculate uptime
    auto now = std::chrono::system_clock::now();
    auto start = std::chrono::system_clock::from_time_t(0); // Approximate
    auto uptime = now - start;
    auto hours = std::chrono::duration_cast<std::chrono::hours>(uptime);
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(uptime % std::chrono::hours(1));
    
    std::stringstream ss;
    ss << hours.count() << "h " << minutes.count() << "m";
    stats.uptime = ss.str();
    
    return stats;
}

bool ShadowWatchDaemon::is_node_process(const std::string& name) {
    return name == "node" || name == "npm" || name == "yarn" || 
           name == "pnpm" || name.find("node") != std::string::npos;
}

bool ShadowWatchDaemon::is_python_process(const std::string& name) {
    return name == "python" || name == "python3" || name == "pip" || 
           name == "pip3" || name.find("python") != std::string::npos;
}

void ShadowWatchDaemon::log_event(const WatchEvent& event) {
    if (!policy_.log_events) return;
    
    // Create log directory if it doesn't exist
    std::string log_dir = policy_.log_file.substr(0, policy_.log_file.find_last_of('/'));
    mkdir(log_dir.c_str(), 0755);
    
    // Check if log rotation is needed
    if (policy_.rotate_logs && should_rotate_log()) {
        rotate_log_file();
    }
    
    std::ofstream log_file(policy_.log_file, std::ios::app);
    if (!log_file.is_open()) return;
    
    // Write structured JSON log entry
    log_file << "{"
             << "\"timestamp\":\"" << event.timestamp << "\""
             << ",\"type\":\"" << event_type_to_string(event.type) << "\""
             << ",\"severity\":\"" << get_event_severity(event.type) << "\""
             << ",\"pid\":" << event.pid
             << ",\"process\":\"" << event.process_name << "\""
             << ",\"description\":\"" << event.description << "\"";
    
    if (!event.package_name.empty()) {
        log_file << ",\"package\":\"" << event.package_name << "\"";
    }
    
    // Add system context
    log_file << ",\"hostname\":\"" << get_hostname() << "\""
             << ",\"daemon_pid\":" << getpid();
    
    log_file << "}" << std::endl;
    log_file.flush();
}

// ---------------------------------------------------------------------------
// should_rotate_log()
//
// Check if log file needs rotation based on size
// ---------------------------------------------------------------------------
bool ShadowWatchDaemon::should_rotate_log() {
    struct stat log_stat;
    if (stat(policy_.log_file.c_str(), &log_stat) != 0) {
        return false; // File doesn't exist
    }
    
    // Parse max_log_size (e.g., "100M", "10G")
    long max_bytes = parse_log_size(policy_.max_log_size);
    return log_stat.st_size >= max_bytes;
}

// ---------------------------------------------------------------------------
// rotate_log_file()
//
// Rotate log files (file.log -> file.log.1, etc.)
// ---------------------------------------------------------------------------
void ShadowWatchDaemon::rotate_log_file() {
    const int max_rotations = 5;
    
    // Move existing rotated logs
    for (int i = max_rotations - 1; i >= 1; i--) {
        std::string old_file = policy_.log_file + "." + std::to_string(i);
        std::string new_file = policy_.log_file + "." + std::to_string(i + 1);
        rename(old_file.c_str(), new_file.c_str());
    }
    
    // Move current log to .1
    std::string rotated_file = policy_.log_file + ".1";
    rename(policy_.log_file.c_str(), rotated_file.c_str());
}

// ---------------------------------------------------------------------------
// Helper functions for logging
// ---------------------------------------------------------------------------
std::string ShadowWatchDaemon::event_type_to_string(WatchEvent::Type type) {
    switch (type) {
        case WatchEvent::CREDENTIAL_ACCESS: return "CREDENTIAL_ACCESS";
        case WatchEvent::MALICIOUS_CONNECTION: return "MALICIOUS_CONNECTION";
        case WatchEvent::SUSPICIOUS_PROCESS: return "SUSPICIOUS_PROCESS";
        case WatchEvent::PACKAGE_INSTALL: return "PACKAGE_INSTALL";
        case WatchEvent::STAGED_PAYLOAD: return "STAGED_PAYLOAD";
        case WatchEvent::POLICY_VIOLATION: return "POLICY_VIOLATION";
        default: return "UNKNOWN";
    }
}

std::string ShadowWatchDaemon::get_event_severity(WatchEvent::Type type) {
    switch (type) {
        case WatchEvent::CREDENTIAL_ACCESS:
        case WatchEvent::MALICIOUS_CONNECTION:
            return "CRITICAL";
        case WatchEvent::SUSPICIOUS_PROCESS:
        case WatchEvent::STAGED_PAYLOAD:
            return "WARNING";
        case WatchEvent::PACKAGE_INSTALL:
            return "INFO";
        case WatchEvent::POLICY_VIOLATION:
            return "WARNING";
        default:
            return "INFO";
    }
}

std::string ShadowWatchDaemon::get_hostname() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "unknown";
}

long ShadowWatchDaemon::parse_log_size(const std::string& size_str) {
    if (size_str.empty()) return 100 * 1024 * 1024; // Default 100MB
    
    long value = std::stol(size_str);
    char unit = size_str.back();
    
    switch (unit) {
        case 'K': case 'k': return value * 1024;
        case 'M': case 'm': return value * 1024 * 1024;
        case 'G': case 'g': return value * 1024 * 1024 * 1024;
        default: return value; // Assume bytes
    }
}

void ShadowWatchDaemon::enforce_policy(const WatchEvent& event) {
    // Policy enforcement based on event type
    if (policy_.kill_on_malicious && 
        (event.type == WatchEvent::CREDENTIAL_ACCESS || 
         event.type == WatchEvent::MALICIOUS_CONNECTION)) {
        
        std::cout << COLOR_RED << "[WATCH-ENFORCE]" << COLOR_RESET
                  << " Terminating malicious process PID:" << event.pid << std::endl;
        
        kill_malicious_process(event.pid);
    }
}

void ShadowWatchDaemon::kill_malicious_process(pid_t pid) {
    if (kill(pid, SIGTERM) == 0) {
        std::cout << COLOR_GREEN << "[WATCH-ENFORCE]" << COLOR_RESET
                  << " Process " << pid << " terminated" << std::endl;
    } else {
        std::cout << COLOR_YELLOW << "[WATCH-ENFORCE]" << COLOR_RESET
                  << " Failed to terminate process " << pid << std::endl;
    }
}

// ---------------------------------------------------------------------------
// detect_package_installations()
//
// Monitor for npm, pip, apt package manager processes
// ---------------------------------------------------------------------------
void ShadowWatchDaemon::detect_package_installations() {
    // This would typically integrate with eBPF process monitoring
    // For now, check for running package manager processes via /proc
    
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return;
    
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Skip non-numeric entries (only look at PID directories)
        if (!isdigit(entry->d_name[0])) continue;
        
        std::string proc_path = "/proc/" + std::string(entry->d_name) + "/comm";
        std::ifstream comm_file(proc_path);
        if (!comm_file.is_open()) continue;
        
        std::string comm;
        std::getline(comm_file, comm);
        
        // Check for package manager processes
        if (comm == "npm" || comm == "pip" || comm == "pip3" || 
            comm == "apt" || comm == "apt-get" || comm == "yarn" || comm == "pnpm") {
            
            // Get command line to see what package is being installed
            std::string cmdline_path = "/proc/" + std::string(entry->d_name) + "/cmdline";
            std::ifstream cmdline_file(cmdline_path);
            std::string cmdline;
            if (cmdline_file.is_open()) {
                std::getline(cmdline_file, cmdline);
                // Replace null chars with spaces for readability
                for (char& c : cmdline) {
                    if (c == '\0') c = ' ';
                }
            }
            
            // Only alert on install operations, not queries
            if (cmdline.find("install") != std::string::npos ||
                cmdline.find("add") != std::string::npos) {
                
                WatchEvent install_event;
                install_event.type = WatchEvent::PACKAGE_INSTALL;
                install_event.pid = std::stoi(entry->d_name);
                install_event.process_name = comm;
                install_event.description = "Package installation detected: " + cmdline;
                install_event.package_name = extract_package_name(cmdline, comm);
                
                auto now = std::chrono::system_clock::now();
                auto time_t = std::chrono::system_clock::to_time_t(now);
                std::stringstream ss;
                ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
                install_event.timestamp = ss.str();
                
                handle_event(install_event);
            }
        }
    }
    
    closedir(proc_dir);
}

// ---------------------------------------------------------------------------
// extract_package_name()
//
// Extract package name from command line
// ---------------------------------------------------------------------------
std::string ShadowWatchDaemon::extract_package_name(const std::string& cmdline, const std::string& manager) {
    // Simple extraction - can be improved
    if (manager == "npm") {
        size_t install_pos = cmdline.find("install");
        if (install_pos != std::string::npos) {
            std::string after_install = cmdline.substr(install_pos + 7);
            std::istringstream iss(after_install);
            std::string package;
            iss >> package;
            return package.empty() ? "unknown" : package;
        }
    } else if (manager == "pip" || manager == "pip3") {
        size_t install_pos = cmdline.find("install");
        if (install_pos != std::string::npos) {
            std::string after_install = cmdline.substr(install_pos + 7);
            std::istringstream iss(after_install);
            std::string package;
            iss >> package;
            return package.empty() ? "unknown" : package;
        }
    } else if (manager == "apt" || manager == "apt-get") {
        size_t install_pos = cmdline.find("install");
        if (install_pos != std::string::npos) {
            std::string after_install = cmdline.substr(install_pos + 7);
            std::istringstream iss(after_install);
            std::string package;
            iss >> package;
            return package.empty() ? "unknown" : package;
        }
    }
    
    return "unknown";
}