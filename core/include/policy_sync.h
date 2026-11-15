#ifndef POLICY_SYNC_H
#define POLICY_SYNC_H

#include <string>
#include <vector>

class PolicySync {
public:
    PolicySync();
    ~PolicySync();

    // Main sync function - fetches from all abuse.ch sources
    bool sync();

    // Get last sync status message
    std::string get_last_error() const { return last_error_; }

private:
    // Fetch functions for different abuse.ch feeds
    bool fetch_feodo_tracker(std::vector<std::string>& ips);
    bool fetch_urlhaus(std::vector<std::string>& domains);
    bool fetch_threatfox(std::vector<std::string>& ips, std::vector<std::string>& domains);

    // Download helper - uses curl
    bool download_url(const std::string& url, std::string& content);

    // Write to files
    bool write_ips_file(const std::vector<std::string>& ips);
    bool write_domains_file(const std::vector<std::string>& domains);

    // Trigger daemon reload
    bool reload_daemon();

    // Error tracking
    std::string last_error_;

    // Paths
    static constexpr const char* THREAT_FEED_DIR = "/etc/shadow-watch/threat-feeds";
    static constexpr const char* IPS_FILE = "/etc/shadow-watch/threat-feeds/ips.txt";
    static constexpr const char* DOMAINS_FILE = "/etc/shadow-watch/threat-feeds/domains.txt";
};

#endif // POLICY_SYNC_H
