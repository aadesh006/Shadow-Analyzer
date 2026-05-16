#include "../include/observer.h"
#include "../include/threat_intel.h"
#include "../bpf/shadow.skel.h"
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <iostream>
#include <signal.h>
#include <fstream>
#include <bpf/bpf.h>
#include "../include/sandbox.h"

const std::string COLOR_RESET = "\033[0m";
const std::string COLOR_MAGENTA = "\033[1;35m";
const std::string COLOR_RED = "\033[1;31m";

struct event_t {
    uint8_t type; 
    uint32_t pid;
    uint32_t ppid;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint16_t family; 
    char filename[256];
    char comm[16];
};

Observer::Observer() : skel(nullptr), rb(nullptr), running(false) {}

Observer::~Observer()
{
    stop();
}

struct path_key {
    char name[64];
};

// 2. ADD THE INJECTION FUNCTION
void inject_dynamic_rules(struct shadow_bpf *skel) {
    std::cout << "[Shadow] Loading dynamic threat intelligence..." << std::endl;

    std::ifstream infile("../shadow_rules.conf"); 
    if (!infile.is_open()) {
        std::cerr << "[Shadow] Warning: Could not open shadow_rules.conf" << std::endl;
        return;
    }

    int map_fd = bpf_map__fd(skel->maps.blocklist);
    std::string line;
    int rule_count = 0;

    while (std::getline(infile, line)) {
        if (line.empty()) continue;

        struct path_key key = {};
        strncpy(key.name, line.c_str(), sizeof(key.name) - 1);
        uint32_t value = 1; 

        int err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
        if (err == 0) {
            std::cout << "  -> Injected LSM Block Rule: " << key.name << std::endl;
            rule_count++;
        }
    }
    std::cout << "[Shadow] Successfully injected " << rule_count << " dynamic rules into Ring 0." << std::endl;
}

bool Observer::start()
{
    skel = shadow_bpf__open_and_load();
    if (!skel) return false;

    int err = shadow_bpf__attach(skel);
    if (err) return false;

    inject_dynamic_rules(skel);

    skel = shadow_bpf__open();
    if (!skel)
    {
        std::cerr << COLOR_RED << "[eBPF] Failed to open BPF skeleton" << COLOR_RESET << std::endl;
        return false;
    }

    if (shadow_bpf__load(skel) != 0)
    {
        std::cerr << COLOR_RED << "[eBPF] Failed to load BPF skeleton into kernel" << COLOR_RESET << std::endl;
        shadow_bpf__destroy(skel);
        skel = nullptr;
        return false;
    }

    if (shadow_bpf__attach(skel) != 0)
    {
        std::cerr << COLOR_RED << "[eBPF] Failed to attach BPF skeleton" << COLOR_RESET << std::endl;
        shadow_bpf__destroy(skel);
        skel = nullptr;
        return false;
    }

    // Set up the Ring Buffer to receive events
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb)
    {
        std::cerr << COLOR_RED << "[eBPF] Failed to create ring buffer" << COLOR_RESET << std::endl;
        return false;
    }

    std::cout << COLOR_MAGENTA << "[eBPF]" << COLOR_RESET << " Kernel probe attached successfully." << std::endl;

    // background thread to continuously poll the buffer
    running = true;
    poll_thread = std::thread(&Observer::poll_events, this);

    return true;
}

void Observer::stop()
{
    running = false;

    // Wait for the background thread to finish cleanly
    if (poll_thread.joinable())
    {
        poll_thread.join();
    }

    if (rb)
    {
        ring_buffer__free(rb);
        rb = nullptr;
    }

    // Detach and destroy the kernel program
    if (skel)
    {
        shadow_bpf__destroy(skel);
        skel = nullptr;
        std::cout << COLOR_MAGENTA << "[eBPF]" << COLOR_RESET << " Kernel probe detached." << std::endl;
    }
}

void Observer::poll_events()
{
    // Continuously check the ring buffer for new data from the kernel
    while (running)
    {
        ring_buffer__poll(rb, 100);
    }
}

int Observer::handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_t *e = static_cast<const struct event_t *>(data);

    // DEMULTIPLEXER
    if (e->type == 1)
    {
        // EVENT: NETWORK
        if (e->family == 2)
        {
            struct in_addr ip_addr;
            ip_addr.s_addr = e->dest_ip;
            std::string raw_ip = inet_ntoa(ip_addr);
            std::string hostname = ThreatIntel::resolve_ipv4(raw_ip);
            bool is_threat = ThreatIntel::is_malicious(hostname);

            std::string status = is_threat ? (COLOR_RED + "[CRITICAL]" + COLOR_RESET)
                                           : (COLOR_MAGENTA + "[NET SAFE]" + COLOR_RESET);

            std::cout << "  " << status
                      << " PID: " << e->pid
                      << " | IPv4: " << raw_ip
                      << " -> " << hostname << std::endl;
        }
    } 
    else if (e->type == 2) { 
        //EVENT: FILE SYSTEM (LSM)
        std::string filename(e->filename);
        std::cout << "\033[1;31m[LSM THREAT BLOCKED] " 
              << "Malware (PID " << e->pid << ") attempted to read restricted file: " 
              << e->filename << "\033[0m" << std::endl;
        
        if (filename.find("passwd") != std::string::npos || 
            filename.find("id_rsa") != std::string::npos) {
            
            std::cout << "  \033[31m[LSM BLOCK NATIVE]\033[0m" 
                      << " PID: " << e->pid 
                      << " | Kernel actively denied access to: " << filename 
                      << " (0ms latency)" << std::endl;
        }
    }
    else if (e->type == 3) { 
        //EVENT: EXECUTION TREE
        std::string parent_name(e->comm);
        std::string target_binary(e->filename);
        
        if (target_binary != "/usr/bin/node" && target_binary != "/usr/bin/npm") {
            std::cout << "  " << COLOR_MAGENTA << "[PROCESS TREE]" << COLOR_RESET 
                      << " PPID: " << e->ppid << " (" << parent_name << ") "
                      << "==> Spawned PID: " << e->pid << " (" << target_binary << ")" << std::endl;
        }
    }
    else if (e->type == 0) { 
        // EVENT: EXECUTION TREE (Matched to Kernel type 0)
        std::string target_binary(e->filename);
        
        if (target_binary != "/usr/bin/node" && target_binary != "/usr/bin/npm") {
        
            std::cout << "  " << COLOR_MAGENTA << "[PROCESS TREE]" << COLOR_RESET 
                      << " PPID: " << e->ppid 
                      << " ==> Spawned PID: " << e->pid 
                      << " (" << target_binary << ")" << std::endl;
        }
    }

    return 0;
}