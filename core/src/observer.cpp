#include "../include/observer.h"
#include "shadow.skel.h"
#include <bpf/libbpf.h>
#include <iostream>

const std::string COLOR_RESET   = "\033[0m";
const std::string COLOR_MAGENTA = "\033[1;35m";
const std::string COLOR_RED     = "\033[1;31m";

Observer::Observer() : skel(nullptr), rb(nullptr), running(false) {}

Observer::~Observer() {
    stop();
}

bool Observer::start() {

    skel = shadow_bpf__open();
    if (!skel) {
        std::cerr << COLOR_RED << "[eBPF] Failed to open BPF skeleton" << COLOR_RESET << std::endl;
        return false;
    }

    if (shadow_bpf__load(skel) != 0) {
        std::cerr << COLOR_RED << "[eBPF] Failed to load BPF skeleton into kernel" << COLOR_RESET << std::endl;
        shadow_bpf__destroy(skel);
        skel = nullptr;
        return false;
    }

    if (shadow_bpf__attach(skel) != 0) {
        std::cerr << COLOR_RED << "[eBPF] Failed to attach BPF skeleton" << COLOR_RESET << std::endl;
        shadow_bpf__destroy(skel);
        skel = nullptr;
        return false;
    }

    //Set up the Ring Buffer to receive events
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        std::cerr << COLOR_RED << "[eBPF] Failed to create ring buffer" << COLOR_RESET << std::endl;
        return false;
    }

    std::cout << COLOR_MAGENTA << "[eBPF]" << COLOR_RESET << " Kernel probe attached successfully." << std::endl;

    //background thread to continuously poll the buffer
    running = true;
    poll_thread = std::thread(&Observer::poll_events, this);

    return true;
}

void Observer::stop() {
    running = false;
    
    // Wait for the background thread to finish cleanly
    if (poll_thread.joinable()) {
        poll_thread.join();
    }
    
    if (rb) {
        ring_buffer__free(rb);
        rb = nullptr;
    }
    
    // Detach and destroy the kernel program
    if (skel) {
        shadow_bpf__destroy(skel);
        skel = nullptr;
        std::cout << COLOR_MAGENTA << "[eBPF]" << COLOR_RESET << " Kernel probe detached." << std::endl;
    }
}


void Observer::poll_events() {

}

int Observer::handle_event(void* ctx, void* data, size_t data_sz) {
    return 0;
}