#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_TYPE_NET 1
#define EVENT_TYPE_FILE 2
#define EVENT_TYPE_EXEC 3

struct event_t {
    u8 type;
    u32 pid;
    u32 ppid;
    
    // Network Specific
    u32 dest_ip;
    u16 dest_port;
    u16 family; 
    
    // File/Exec Specific
    char filename[256];
    char comm[16];
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
        if (first_byte == 127 || first_byte == 10) return 0;

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

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

//HOOK 3: The Execution Kill Chain
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_EXEC;
    e->pid = pid;
    e->ppid = ppid;

    // Grab the name of the parent process (e.g., "npm" or "sh")
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Grab the path of the new binary being launched (e.g., "/usr/bin/cat")
    const char *arg_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), arg_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";