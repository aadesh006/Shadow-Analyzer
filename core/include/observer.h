#pragma once
#include <thread>
#include <atomic>
#include <string>
#include <cstddef>

struct shadow_bpf;
struct ring_buffer;

class Observer {
public:
    Observer();
    ~Observer();

    bool start();
    void stop();

    bool        threat_detected = false;
    std::string threat_description;

private:
    struct shadow_bpf  *skel;
    struct ring_buffer *rb;

    std::thread       poll_thread;
    std::atomic<bool> running;

    void       poll_events();
    static int handle_event(void *ctx, void *data, size_t data_sz);
};