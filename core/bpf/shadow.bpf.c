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

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    
    // Get the Process ID (PID) that triggered the system call
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[1];
    short family;
    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);

    if (family != 2 && family != 10) {
        return 0; 
    }

    // Reserve space in the Ring Buffer
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->family = family;

    // Extract the IP address based on the network family
    if (family == 2) {
        // IPv4 translation
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), uservaddr);
        e->dest_ip = addr.sin_addr.s_addr;
        e->dest_port = addr.sin_port;
    } else {
        // IPv6 translation
        struct sockaddr_in6 addr6;
        bpf_probe_read_user(&addr6, sizeof(addr6), uservaddr);
        e->dest_ip = 0;
        e->dest_port = addr6.sin6_port;
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// The kernel requires a GPL compatible license to load eBPF programs
char LICENSE[] SEC("license") = "Dual BSD/GPL";