#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_TYPE_NET 1
#define EVENT_TYPE_FILE 2

struct event_t {
    u8 type; // 1 = Network, 2 = File
    u32 pid;
    
    u32 dest_ip;
    u16 dest_port;
    u16 family; 
    
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

//HOOK 1: The Network Sentinel
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[1];
    short family;
    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);

    if (family == 2) {
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), uservaddr);
        
        u8 first_byte = addr.sin_addr.s_addr & 0xFF;
        if (first_byte == 127 || first_byte == 10) {
            return 0;
        }

        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) return 0;

        e->type = EVENT_TYPE_NET;
        e->pid = pid;
        e->family = family;
        e->dest_ip = addr.sin_addr.s_addr;
        e->dest_port = addr.sin_port;
        bpf_ringbuf_submit(e, 0);

    } else if (family == 10) {
        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) return 0;

        e->type = EVENT_TYPE_NET;
        e->pid = pid;
        e->family = family;
        e->dest_ip = 0;
        e->dest_port = 0;
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

//HOOK 2: The File System Sentinel
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_FILE;
    e->pid = pid;

    // ctx->args[1] holds the pointer to the filename string in user memory
    const char *pathname = (const char *)ctx->args[1];
    
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
