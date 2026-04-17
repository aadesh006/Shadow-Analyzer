#pragma once
#include <thread>
#include <atomic>
#include <cstddef>

struct shadow_bpf;
struct ring_buffer;

class Observer {
public:
    Observer();
    ~Observer();

    // Loads the probe into the kernel and starts listening
    bool start();
    
    void stop();

private:
    struct shadow_bpf* skel;
    struct ring_buffer* rb;
    
    std::thread poll_thread;
    std::atomic<bool> running;

    // The polling loop that runs in the background
    void poll_events();

    // The static callback function triggered every time the kernel writes to the buffer
    static int handle_event(void* ctx, void* data, size_t data_sz);
};