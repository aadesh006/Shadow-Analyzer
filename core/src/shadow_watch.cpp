#include "../include/shadow_watch.h"
#include "../include/observer.h"
#include "../include/static_scanner.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <sys/stat.h>
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
    
    // Load configuration
    if (!load_config(config_path)) {
        std::cerr << COLOR_RED << "[WATCH] Failed to load config from " 
                  << config_path << COLOR_RESET << std::endl;
        // Continue with defaults
    }
    
    // Initialize eBPF observer (same as sandbox but system-wide)
    observer_ = std::make_unique<Observer>();
    if (!observer_->start()) {
        std::cerr << COLOR_RED << "[WATCH] Failed to initialize eBPF observer" 
                  << COLOR_RESET << std::endl;
        return false;
    }
    
    // Create log directory
    system("mkdir -p /var/log/shadow 2>/dev/null");
    
    // Start monitoring thread
    running_ = true;
    monitor_thread_ = std::make_unique<std::thread>(&ShadowWatchDaemon::monitor_loop, this);
    
    std::cout << COLOR_GREEN << "[WATCH] Shadow Watch daemon started successfully" 
              << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "[WATCH]" << COLOR_RESET 
              << " Monitoring: Node.js=" << (policy_.monitor_node_processes ? "ON" : "OFF")
              << ", Python=" << (policy_.monitor_python_processes ? "ON" : "OFF")
              << ", All=" << (policy_.monitor_all_processes ? "ON" : "OFF") << std::endl;
    
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
    // For now, use default policy
    // TODO: Implement config file parsing
    policy_ = WatchPolicy{}; // Default values
    
    std::cout << COLOR_CYAN << "[WATCH]" << COLOR_RESET 
              << " Using default configuration (config parsing not yet implemented)" << std::endl;
    
    return true;
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
        // Poll for eBPF events (same observer as sandbox but no PID filtering)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Check for new process spawns that we should monitor
        // TODO: Integrate with actual eBPF event processing
        
        // For now, simulate event detection
        static int event_counter = 0;
        if (++event_counter % 100 == 0) { // Every 10 seconds
            // Simulate a suspicious event for testing
            WatchEvent test_event;
            test_event.type = WatchEvent::SUSPICIOUS_PROCESS;
            test_event.pid = 12345;
            test_event.process_name = "node";
            test_event.description = "Simulated suspicious process spawn";
            test_event.package_name = "test-package";
            
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
            test_event.timestamp = ss.str();
            
            handle_event(test_event);
        }
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
    std::ofstream log_file("/var/log/shadow/watch.log", std::ios::app);
    if (!log_file.is_open()) return;
    
    // Write JSON-structured log entry
    log_file << "{\"timestamp\":\"" << event.timestamp << "\""
             << ",\"type\":\"" << event.type << "\""
             << ",\"pid\":" << event.pid
             << ",\"process\":\"" << event.process_name << "\""
             << ",\"description\":\"" << event.description << "\"";
    
    if (!event.package_name.empty()) {
        log_file << ",\"package\":\"" << event.package_name << "\"";
    }
    
    log_file << "}" << std::endl;
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