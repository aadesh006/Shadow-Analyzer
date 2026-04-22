#include "../include/threat_intel.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

bool ThreatIntel::is_malicious(const std::string& hostname) {
    if (hostname.find("evil.com") != std::string::npos) return true;
    if (hostname.find("pastebin.com") != std::string::npos) return true;
    return false;
}