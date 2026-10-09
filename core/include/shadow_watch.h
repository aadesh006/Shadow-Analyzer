#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <atomic>
#include <thread>
#include <memory>
#include <mutex>

// Forward declarations
class Observer;

// ---------------------------------------------------------------------------
// WatchEvent
//
// Represents a security event detected by the shadow watch daemon
// ---------------------------------------------------------------------------
struct WatchEvent {
    enum Type {
        CREDENTIAL_ACCESS,     // LSM blocked credential file access
        MALICIOUS_CONNECTION,  // Connection to known C2 server
        SUSPICIOUS_PROCESS,    // Unexpected process spawn (curl, wget, etc.)
        PACKAGE_INSTALL,       // Package manager installation detected
        STAGED_PAYLOAD,        // Post-install static scan finding
        POLICY_VIOLATION       // Custom policy rule violation
    };
    
    Type type;
    pid_t pid;
    std::string process_name;
    std::string description;
    std::string timestamp;
    std::string package_name; // If associated with an npm package
};

// ---------------------------------------------------------------------------
// WatchPolicy
//
// Configurable policy for what the daemon should monitor and how to respond
// ---------------------------------------------------------------------------
struct WatchPolicy {
    // Process monitoring
    bool monitor_node_processes = true;     // All node/npm/yarn processes
    bool monitor_python_processes = true;   // All python/pip processes  
    bool monitor_all_processes = false;     // All system processes (high overhead)
    
    // Package managers to watch
    bool watch_npm = true;
    bool watch_pip = true;
    bool watch_apt = true;
    bool watch_yarn = true;
    bool watch_pnpm = true;
    
    // Response actions
    bool log_events = true;                 // Log to /var/log/shadow/watch.log
    bool send_alerts = false;               // Send to SIEM/webhook (future)
    bool kill_on_malicious = false;         // Terminate malicious processes
    bool block_connections = false;         // Block network connections (future)
    
    // Network monitoring
    bool monitor_outbound_connections = true;
    bool block_known_malicious = true;
    bool alert_on_suspicious = true;
    
    // Static scanning
    bool scan_new_packages = true;          // Scan packages as they're installed
    bool scan_existing_packages = false;    // Periodic scan of existing node_modules
    bool enable_static_scan = false;        // Use static scanner (disabled due to false positives)
    
    // Alert thresholds
    int suspicious_connection_threshold = 5;
    int credential_access_threshold = 1;
    int max_events_per_minute = 10;         // Rate limiting
    
    // Logging settings
    std::string log_file = "/var/log/shadow/watch.log";
    std::string log_level = "info";
    std::string max_log_size = "100M";
    bool rotate_logs = true;
    
    // Advanced settings
    int scan_frequency_ms = 500;            // How often to check for events
    int event_retention = 1000;             // Max events to keep in memory
};

// ---------------------------------------------------------------------------
// ShadowWatchDaemon
//
// Always-on EDR daemon that monitors system-wide Node.js/Python processes
// for supply chain threats. Uses the same eBPF hooks as the sandbox but
// applied to the entire host system.
//
// Key capabilities:
//   1. Real-time process monitoring - All Node.js processes watched for
//      credential access, malicious network connections, suspicious spawns
//   2. Package installation monitoring - Detects when packages are installed
//      and runs static analysis automatically  
//   3. Policy enforcement - Configurable responses (log, alert, kill process)
//   4. Event correlation - Links events to specific packages when possible
//   5. Staged payload detection - Monitors for delayed activation of malware
//
// Architecture:
//   - Uses same eBPF programs as sandbox (LSM + tracepoints)
//   - Runs as systemd service with root privileges
//   - Filters events to focus on package manager processes
//   - Maintains allowlist of legitimate CDN connections
//   - Logs to /var/log/shadow/ with structured JSON format
//
// Usage:
//   sudo shadow watch start   [--config /etc/shadow/watch.conf]
//   sudo shadow watch stop
//   sudo shadow watch status
//   sudo shadow watch logs    [--tail] [--package <name>]
// ---------------------------------------------------------------------------
class ShadowWatchDaemon {
public:
    ShadowWatchDaemon();
    ~ShadowWatchDaemon();

    // Daemon lifecycle
    bool start(const std::string& config_path = "/etc/shadow/watch.conf");
    void stop();
    bool is_running() const { return running_; }
    
    // Configuration
    bool load_config(const std::string& config_path);
    const WatchPolicy& get_policy() const { return policy_; }
    
    // Config parsing helpers
    void parse_config_option(const std::string& section, const std::string& key, const std::string& value);
    bool parse_bool(const std::string& value);
    
    // Daemon management  
    bool daemonize();
    
    // Event handling
    void handle_event(const WatchEvent& event);
    std::vector<WatchEvent> get_recent_events(int limit = 100) const;
    
    // Status and monitoring
    struct Stats {
        int total_events = 0;
        int credential_blocks = 0;
        int malicious_connections = 0;
        int suspicious_processes = 0;
        int packages_scanned = 0;
        std::string uptime;
        std::string last_event_time;
    };
    Stats get_stats() const;
    
private:
    // Core monitoring thread
    void monitor_loop();
    
    // Event processing
    bool should_monitor_pid(pid_t pid);
    std::string get_process_name(pid_t pid);
    std::string get_package_for_pid(pid_t pid);
    void log_event(const WatchEvent& event);
    void send_alert(const WatchEvent& event);
    
    // Logging helpers
    bool should_rotate_log();
    void rotate_log_file();
    std::string event_type_to_string(WatchEvent::Type type);
    std::string get_event_severity(WatchEvent::Type type);
    std::string get_hostname();
    long parse_log_size(const std::string& size_str);
    
    // Process filtering
    bool is_package_manager_process(const std::string& name);
    bool is_node_process(const std::string& name);
    bool is_python_process(const std::string& name);
    
    // Policy enforcement
    void enforce_policy(const WatchEvent& event);
    void kill_malicious_process(pid_t pid);
    
    // Package detection
    void detect_package_installations();
    std::string extract_package_name(const std::string& cmdline, const std::string& manager);
    
    // Static scanning integration
    void scan_new_package_installation(const std::string& package_path);
    
private:
    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> monitor_thread_;
    std::unique_ptr<Observer> observer_;
    
    WatchPolicy policy_;
    mutable std::mutex events_mutex_;
    std::vector<WatchEvent> recent_events_;
    
    // Process tracking
    std::unordered_set<pid_t> monitored_pids_;
    std::unordered_set<std::string> known_packages_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
    std::string start_time_;
};