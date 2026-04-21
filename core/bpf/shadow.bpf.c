#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct event_t {
    u32 pid;
    u32 dest_ip;
    u16 dest_port;
    u16 family;
};

//A 256KB lockless shared memory queue
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");