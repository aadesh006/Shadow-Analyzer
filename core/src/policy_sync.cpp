#include "../include/policy_sync.h"
#include "../include/shadow_watch.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <sys/stat.h>
#include <curl/curl.h>

// abuse.ch feed URLs
static const char* FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
static const char* URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text_online/";
static const char* THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/ip-port/recent/";

// Curl write callback
static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

PolicySync::PolicySync() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

PolicySync::~PolicySync() {
    curl_global_cleanup();
}

bool PolicySync::download_url(const std::string& url, std::string& content) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        last_error_ = "Failed to initialize curl";
        return false;
    }

    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &content);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Shadow-Analyzer/1.0");

    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        last_error_ = std::string("Curl error: ") + curl_easy_strerror(res);
        curl_easy_cleanup(curl);
        return false;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code != 200) {
        last_error_ = "HTTP error: " + std::to_string(http_code);
        return false;
    }

    return true;
}

bool PolicySync::fetch_feodo_tracker(std::vector<std::string>& ips) {
    std::cout << "[Policy] Fetching Feodo Tracker (C2 IPs)..." << std::endl;
    
    std::string content;
    if (!download_url(FEODO_TRACKER_URL, content)) {
        std::cerr << "[Policy] Failed to fetch Feodo Tracker: " << last_error_ << std::endl;
        return false;
    }

    // Parse line by line
    std::istringstream stream(content);
    std::string line;
    int count = 0;

    while (std::getline(stream, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        
        // Trim whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        
        std::string ip = line.substr(start, end - start + 1);
        ips.push_back(ip);
        count++;
    }

    std::cout << "[Policy] Fetched " << count << " IPs from Feodo Tracker" << std::endl;
    return true;
}

bool PolicySync::fetch_urlhaus(std::vector<std::string>& domains) {
    std::cout << "[Policy] Fetching URLhaus (malicious domains)..." << std::endl;
    
    std::string content;
    if (!download_url(URLHAUS_URL, content)) {
        std::cerr << "[Policy] Failed to fetch URLhaus: " << last_error_ << std::endl;
        return false;
    }

    // Parse URLs and extract domains
    std::istringstream stream(content);
    std::string line;
    std::set<std::string> unique_domains; // Use set to avoid duplicates

    while (std::getline(stream, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        
        // Extract domain from URL
        // Format: http://domain.com/path or https://domain.com/path
        size_t proto_end = line.find("://");
        if (proto_end == std::string::npos) continue;
        
        size_t domain_start = proto_end + 3;
        size_t domain_end = line.find('/', domain_start);
        if (domain_end == std::string::npos) {
            domain_end = line.length();
        }
        
        std::string domain = line.substr(domain_start, domain_end - domain_start);
        
        // Remove port if present
        size_t port_pos = domain.find(':');
        if (port_pos != std::string::npos) {
            domain = domain.substr(0, port_pos);
        }
        
        if (!domain.empty()) {
            unique_domains.insert(domain);
        }
    }

    domains.assign(unique_domains.begin(), unique_domains.end());
    std::cout << "[Policy] Fetched " << domains.size() << " domains from URLhaus" << std::endl;
    return true;
}

bool PolicySync::fetch_threatfox(std::vector<std::string>& ips, std::vector<std::string>& domains) {
    std::cout << "[Policy] Fetching ThreatFox (recent IOCs)..." << std::endl;
    
    std::string content;
    if (!download_url(THREATFOX_URL, content)) {
        std::cerr << "[Policy] Failed to fetch ThreatFox: " << last_error_ << std::endl;
        return false;
    }

    // Parse CSV format
    std::istringstream stream(content);
    std::string line;
    int ip_count = 0;
    int domain_count = 0;
    bool first_line = true;

    while (std::getline(stream, line)) {
        // Skip header and comments
        if (first_line || line.empty() || line[0] == '#') {
            first_line = false;
            continue;
        }

        // CSV format: field1,field2,ioc_value,ioc_type,...
        // We need to extract IPs and domains
        std::istringstream line_stream(line);
        std::string field;
        std::vector<std::string> fields;

        while (std::getline(line_stream, field, ',')) {
            fields.push_back(field);
        }

        if (fields.size() < 4) continue;

        std::string ioc_value = fields[2];
        std::string ioc_type = fields[3];

        // Check if it's an IP or domain
        if (ioc_type.find("ip") != std::string::npos && 
            ioc_value.find('.') != std::string::npos) {
            ips.push_back(ioc_value);
            ip_count++;
        } else if (ioc_type.find("domain") != std::string::npos ||
                   ioc_type.find("url") != std::string::npos) {
            domains.push_back(ioc_value);
            domain_count++;
        }
    }

    std::cout << "[Policy] Fetched " << ip_count << " IPs and " 
              << domain_count << " domains from ThreatFox" << std::endl;
    return true;
}

bool PolicySync::write_ips_file(const std::vector<std::string>& ips) {
    // Create directory if it doesn't exist
    mkdir(THREAT_FEED_DIR, 0755);

    std::ofstream file(IPS_FILE);
    if (!file.is_open()) {
        last_error_ = std::string("Failed to open ") + IPS_FILE;
        return false;
    }

    file << "# Shadow Threat Intelligence - Malicious IPs" << std::endl;
    file << "# Last updated: " << __DATE__ << " " << __TIME__ << std::endl;
    file << "# Sources: Feodo Tracker, ThreatFox" << std::endl;
    file << "#" << std::endl;

    for (const auto& ip : ips) {
        file << ip << std::endl;
    }

    file.close();
    std::cout << "[Policy] Wrote " << ips.size() << " IPs to " << IPS_FILE << std::endl;
    return true;
}

bool PolicySync::write_domains_file(const std::vector<std::string>& domains) {
    // Create directory if it doesn't exist
    mkdir(THREAT_FEED_DIR, 0755);

    std::ofstream file(DOMAINS_FILE);
    if (!file.is_open()) {
        last_error_ = std::string("Failed to open ") + DOMAINS_FILE;
        return false;
    }

    file << "# Shadow Threat Intelligence - Malicious Domains" << std::endl;
    file << "# Last updated: " << __DATE__ << " " << __TIME__ << std::endl;
    file << "# Sources: URLhaus, ThreatFox" << std::endl;
    file << "#" << std::endl;

    for (const auto& domain : domains) {
        file << domain << std::endl;
    }

    file.close();
    std::cout << "[Policy] Wrote " << domains.size() << " domains to " << DOMAINS_FILE << std::endl;
    return true;
}

bool PolicySync::reload_daemon() {
    std::cout << "[Policy] Triggering daemon reload..." << std::endl;
    
    // Send RELOAD_CONFIG command to daemon via IPC
    std::string response;
    if (!ShadowWatchDaemon::send_ipc_command(IPCCommand::RELOAD_CONFIG, response)) {
        std::cerr << "[Policy] Warning: Failed to reload daemon. Is it running?" << std::endl;
        std::cerr << "[Policy] You may need to restart manually: shadow watch stop && shadow watch start" << std::endl;
        return false;
    }

    std::cout << "[Policy] " << response << std::endl;
    return true;
}

bool PolicySync::sync() {
    std::cout << "=== Shadow Policy Sync ===" << std::endl;
    std::cout << "[Policy] Fetching threat intelligence from abuse.ch..." << std::endl;

    std::vector<std::string> all_ips;
    std::vector<std::string> all_domains;

    // Fetch from all sources
    bool success = true;

    if (!fetch_feodo_tracker(all_ips)) {
        success = false;
    }

    if (!fetch_urlhaus(all_domains)) {
        success = false;
    }

    std::vector<std::string> threatfox_ips;
    std::vector<std::string> threatfox_domains;
    if (fetch_threatfox(threatfox_ips, threatfox_domains)) {
        all_ips.insert(all_ips.end(), threatfox_ips.begin(), threatfox_ips.end());
        all_domains.insert(all_domains.end(), threatfox_domains.begin(), threatfox_domains.end());
    } else {
        success = false;
    }

    if (all_ips.empty() && all_domains.empty()) {
        std::cerr << "[Policy] Error: Failed to fetch any threat data" << std::endl;
        return false;
    }

    // Write to files
    if (!write_ips_file(all_ips)) {
        std::cerr << "[Policy] Error: " << last_error_ << std::endl;
        return false;
    }

    if (!write_domains_file(all_domains)) {
        std::cerr << "[Policy] Error: " << last_error_ << std::endl;
        return false;
    }

    std::cout << "[Policy] Sync complete! Total: " << all_ips.size() 
              << " IPs, " << all_domains.size() << " domains" << std::endl;

    // Auto-reload daemon
    reload_daemon();

    return success;
}
