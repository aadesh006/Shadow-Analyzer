#include "../include/observer.h"
#include "../include/threat_intel.h"
#include "../bpf/shadow.skel.h"
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <iostream>
#include <signal.h>

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

bool Observer::start()
{

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

    return 0;
}