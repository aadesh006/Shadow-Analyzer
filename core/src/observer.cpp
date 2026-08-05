#include "../include/observer.h"
#include "../include/threat_intel.h"
#include "../bpf/shadow.skel.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>


#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"


struct event_t {
    uint32_t type;
    uint32_t pid;
    uint32_t ppid;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint16_t family;
    uint64_t ts_ns;
    char     filename[256];
    char     comm[16];
};

struct path_key {
    char name[64];
};

Observer::Observer() : skel(nullptr), rb(nullptr), running(false),
                       threat_detected(false) {}

Observer::~Observer() {
    stop();
}

static void inject_dynamic_rules(struct shadow_bpf *skel) {
    std::cout << "[Shadow] Loading dynamic threat intelligence..." << std::endl;

    // Check multiple locations
    std::vector<std::string> rule_paths = {
        "/etc/shadow-analyzer/shadow_rules.conf",
        "../shadow_rules.conf",
        "./shadow_rules.conf"
    };

    std::ifstream infile;
    for (const auto& path : rule_paths) {
        infile.open(path);
        if (infile.is_open()) {
            std::cout << "[Shadow] Rules loaded from: " << path << std::endl;
            break;
        }
    }

    if (!infile.is_open()) {
        std::cerr << COLOR_YELLOW
                  << "[Shadow] Warning: shadow_rules.conf not found. "
                  << "LSM blocklist will be empty."
                  << COLOR_RESET << std::endl;
        return;
    }

    int map_fd = bpf_map__fd(skel->maps.blocklist);
    std::string line;
    int count = 0;

    while (std::getline(infile, line)) {
        if (line.empty() || line[0] == '#') continue;

        struct path_key key = {};
        strncpy(key.name, line.c_str(), sizeof(key.name) - 1);
        uint32_t value = 1; // 1 = block

        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) == 0) {
            std::cout << "  " COLOR_RED "[RULE]" COLOR_RESET
                      << " LSM block active: " << key.name << std::endl;
            count++;
        }
    }

    std::cout << "[Shadow] " << count
              << " rules injected into Ring 0 kernel map." << std::endl;
}

void Observer::register_sandbox_pid(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);

    char link_target[256];
    ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
    if (len == -1) {
        std::cerr << COLOR_RED << "[Shadow] Failed to read sandbox PID namespace." << COLOR_RESET << std::endl;
        return;
    }
    link_target[len] = '\0';

    uint64_t ns_inum = 0;
    std::string s(link_target);
    size_t start = s.find('[');
    size_t end = s.find(']');
    if (start != std::string::npos && end != std::string::npos) {
        ns_inum = std::stoull(s.substr(start + 1, end - start - 1));
    }

    if (ns_inum == 0) {
        std::cerr << COLOR_RED << "[Shadow] Could not parse sandbox namespace ID." << COLOR_RESET << std::endl;
        return;
    }

    uint32_t key = 0;
    int map_fd = bpf_map__fd(skel->maps.sandbox_ns);
    if (bpf_map_update_elem(map_fd, &key, &ns_inum, BPF_ANY) == 0) {
        std::cout << COLOR_MAGENTA << "[eBPF]" << COLOR_RESET
                  << " Sandbox namespace registered: " << ns_inum << std::endl;
    }
}

static void inject_ip_blocklist(struct shadow_bpf *skel) {
    std::vector<std::string> paths = {
        "/etc/shadow-analyzer/shadow_ip_blocklist.conf",
        "../shadow_ip_blocklist.conf",
        "./shadow_ip_blocklist.conf"
    };

    std::ifstream infile;
    for (const auto& path : paths) {
        infile.open(path);
        if (infile.is_open()) break;
    }
    if (!infile.is_open()) return; // no IP rules — not fatal, file blocklist still works

    int map_fd = bpf_map__fd(skel->maps.ip_blocklist);
    std::string line;
    int count = 0;

    while (std::getline(infile, line)) {
        if (line.empty() || line[0] == '#') continue;

        struct in_addr addr;
        if (inet_pton(AF_INET, line.c_str(), &addr) != 1) continue; // skip malformed lines

        uint32_t key = addr.s_addr;
        uint32_t value = 1;
        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) == 0) count++;
    }

    std::cout << "[Shadow] " << count << " known-malicious IPs loaded into Ring 0 block map." << std::endl;
}

bool Observer::start() {

    skel = shadow_bpf__open();
    if (!skel) {
        std::cerr << COLOR_RED
                  << "[eBPF] Failed to open BPF skeleton."
                  << COLOR_RESET << std::endl;
        return false;
    }

    //Load (JIT-compile and verify) into kernel
    if (shadow_bpf__load(skel) != 0) {
        std::cerr << COLOR_RED
                  << "[eBPF] Failed to load BPF programs into kernel."
                  << COLOR_RESET << std::endl;
        shadow_bpf__destroy(skel);
        skel = nullptr;
        return false;
    }

    //Inject rules into the loaded skeleton's maps
    inject_dynamic_rules(skel);
    inject_ip_blocklist(skel);

    //Attach hooks to the kernel
    if (shadow_bpf__attach(skel) != 0) {
        std::cerr << COLOR_RED
                  << "[eBPF] Failed to attach BPF hooks."
                  << COLOR_RESET << std::endl;
        shadow_bpf__destroy(skel);
        skel = nullptr;
        return false;
    }

    //Create ring buffer — passes 'this' so handle_event
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                          handle_event, this, NULL);
    if (!rb) {
        std::cerr << COLOR_RED
                  << "[eBPF] Failed to create ring buffer."
                  << COLOR_RESET << std::endl;
        return false;
    }

    std::cout << COLOR_MAGENTA << "[eBPF]" << COLOR_RESET
              << " Kernel probe attached. All hooks live." << std::endl;

    //Start background polling thread
    running = true;
    poll_thread = std::thread(&Observer::poll_events, this);

    return true;
}

void Observer::stop() {
    running = false;

    if (poll_thread.joinable())
        poll_thread.join();

    if (rb) {
        ring_buffer__free(rb);
        rb = nullptr;
    }

    if (skel) {
        shadow_bpf__destroy(skel);
        skel = nullptr;
        std::cout << COLOR_MAGENTA << "[eBPF]" << COLOR_RESET
                  << " Kernel hooks detached." << std::endl;
    }
}

void Observer::poll_events() {
    while (running) {
        ring_buffer__poll(rb, 100); // 100ms timeout
    }
}

int Observer::handle_event(void *ctx, void *data, size_t data_sz) {
    Observer *self = static_cast<Observer *>(ctx);
    const struct event_t *e = static_cast<const struct event_t *>(data);

    //Filter host system noise
    std::string comm(e->comm);
if (comm == "systemd-resolve" ||
    comm == "systemd"         ||
    comm == "shadow"          ||
    comm == "code"            ||
    comm == "Chrome_ChildIOT" ||
    comm == "chrome"          ||
    comm == "sh"              ||
    comm == "umount"          ||
    comm == "rm") {
    return 0;
}

    //Network Connection
    if (e->type == 1) {

    if (e->family == 10) { // AF_INET6
    // npm legitimately uses IPv6 to reach registry.npmjs.org
    std::cout << "  " COLOR_CYAN "[NET6]" COLOR_RESET
              << " PID: " << e->pid
              << " Process: " << e->comm
              << " IPv6 outbound"
              << std::endl;
    // Do NOT set threat_detected for IPv6 until proper classification exists
    }

    if (e->family == 2) {
        struct in_addr addr;
        addr.s_addr = e->dest_ip;
        std::string raw_ip = inet_ntoa(addr); // just converts bytes to string, no DNS

        bool malicious = ThreatIntel::is_malicious(raw_ip);
        bool trusted   = ThreatIntel::is_trusted_cdn(raw_ip);

        if (malicious) {
            std::cout << "  " COLOR_RED "[THREAT]" COLOR_RESET
                      << " C2 callback! PID: " << e->pid
                      << " Process: " << e->comm
                      << " -> " << raw_ip
                      << " Port: " << e->dest_port
                      << std::endl;
            self->threat_detected    = true;
            self->threat_description = "C2 connection to " + raw_ip;

        } else if (!trusted) {
            std::cout << "  " COLOR_YELLOW "[SUSPICIOUS]" COLOR_RESET
                      << " Non-CDN outbound. PID: " << e->pid
                      << " Process: " << e->comm
                      << " -> " << raw_ip
                      << " Port: " << e->dest_port
                      << std::endl;
        } else {
            std::cout << "  " COLOR_GREEN "[NET]" COLOR_RESET
                      << " PID: " << e->pid
                      << " -> " << raw_ip
                      << " Port: " << e->dest_port
                      << std::endl;
        }
    }
}

    //LSM File Block
    else if (e->type == 2) {
        std::string filename(e->filename);

        std::cout << "\n  " COLOR_RED
                  << "╔══════════════════════════════════════════╗\n"
                  << "  ║       LSM THREAT BLOCKED AT RING 0       ║\n"
                  << "  ╚══════════════════════════════════════════╝"
                  << COLOR_RESET << "\n"
                  << "  Process:  " << e->comm << " (PID " << e->pid << ")\n"
                  << "  Attempted: read " << filename << "\n"
                  << "  Result:    EPERM — file never opened\n"
                  << "  Latency:   0ms (Ring 0 native block)\n"
                  << std::endl;

        self->threat_detected    = true;
        self->threat_description = "Credential access blocked: " + filename;
    }

    //Process Spawn
    else if (e->type == 3) {
        std::string binary(e->filename);
        std::string parent(e->comm);

        bool is_expected = (
            binary.find("npm")    != std::string::npos ||
            binary.find("node")   != std::string::npos
        );

        if (!is_expected) {
            std::cout << "  " COLOR_MAGENTA "[PROCESS]" COLOR_RESET
                      << " " << parent
                      << " (PPID " << e->ppid << ")"
                      << " spawned: " << binary
                      << " (PID " << e->pid << ")"
                      << std::endl;

            // Spawning curl, wget, python, perl, ruby during postinstall
            bool is_downloader = (
                binary.find("curl")   != std::string::npos ||
                binary.find("wget")   != std::string::npos ||
                binary.find("python") != std::string::npos ||
                binary.find("perl")   != std::string::npos ||
                binary.find("ruby")   != std::string::npos ||
                binary.find("bash")   != std::string::npos
            );

            if (is_downloader) {
                std::cout << "  " COLOR_RED "[ALERT]" COLOR_RESET
                          << " Suspicious process spawned during install: "
                          << binary << std::endl;
                self->threat_detected    = true;
                self->threat_description = "Suspicious spawn: " + binary;
            }
        }
    }
    
    else if (e->type == 4) {
    std::cout << "  " COLOR_RED "[ALERT]" COLOR_RESET
              << " Anonymous memory execution attempt (memfd_create)!"
              << " PID: " << e->pid
              << " Process: " << e->comm
              << std::endl;
    self->threat_detected    = true;
    self->threat_description = "memfd_create: fileless execution attempt by " 
                               + std::string(e->comm);
    }

    else if (e->type == 5) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t now_ns = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
        uint64_t latency_ns = now_ns - e->ts_ns;

        struct in_addr addr;
        addr.s_addr = e->dest_ip;

        std::cout << "\n  " COLOR_RED
                  << "╔══════════════════════════════════════════╗\n"
                  << "  ║     CONNECTION BLOCKED AT RING 0         ║\n"
                  << "  ╚══════════════════════════════════════════╝"
                  << COLOR_RESET << "\n"
                  << "  Process:   " << e->comm << " (PID " << e->pid << ")\n"
                  << "  Attempted: connect to " << inet_ntoa(addr) << "\n"
                  << "  Result:    EPERM — connection never established\n"
                  << "  Latency:   " << latency_ns << "ns (kernel timestamp to userspace read)\n"
                  << std::endl;

        self->threat_detected    = true;
        self->threat_description = "C2 connection blocked to " + std::string(inet_ntoa(addr));
    }

    return 0;
}