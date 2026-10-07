#pragma once
#include <thread>
#include <atomic>
#include <string>
#include <set>
#include <cstddef>

struct shadow_bpf;
struct ring_buffer;

class Observer {
public:
    Observer();
    ~Observer();

    bool start();
    void stop();
    void register_sandbox_pid(pid_t pid);

    bool        threat_detected = false;
    std::string threat_description;
    int         suspicious_connections = 0; // non-CDN, non-C2 outbound connections

private:
    struct shadow_bpf  *skel;
    struct ring_buffer *rb;

    std::thread       poll_thread;
    std::atomic<bool> running;

    // Tracks PIDs that have already triggered an ALERT this run.
    // Prevents the same binary firing 4 alerts when execve tries
    // each PATH entry (/usr/bin/curl, /usr/sbin/curl, etc.).
    std::set<uint32_t> seen_alert_pids;

    void       poll_events();
    static int handle_event(void *ctx, void *data, size_t data_sz);
};