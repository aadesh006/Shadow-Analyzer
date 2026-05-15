#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET   2
#define AF_INET6  10

#define EPERM 1

struct event_t {
    u32 type;
    u32 pid;
    u32 ppid;
    u32 family;     // AF_INET=2, AF_INET6=10
    u32 dest_ip;
    u16 dest_port;
    char filename[256];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


//THE EXECVE HOOK (Process Tree)
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 pid  = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 3;
    e->pid  = pid;
    e->ppid = ppid;

    const char *prog_name = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), prog_name);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}


//THE NETWORK HOOK

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Read the sockaddr struct from userspace
    struct sockaddr sa;
    void* uaddr = (void*)ctx->args[1];
    if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) != 0)
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type   = 1;
    e->pid    = pid;
    e->family = sa.sa_family;

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sa4;
        if (bpf_probe_read_user(&sa4, sizeof(sa4), uaddr) == 0) {
            e->dest_ip   = sa4.sin_addr.s_addr;
            e->dest_port = __builtin_bswap16(sa4.sin_port);
        }
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}


//HE X-RAY BEHAVIORAL LSM HOOK
SEC("lsm/file_open")
int BPF_PROG(restrict_files, struct file *file) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    //Only watch risky shells and engines
    int is_risky = 0;
    if (comm[0] == 'c' && comm[1] == 'a' && comm[2] == 't') is_risky = 1;
    if (comm[0] == 's' && comm[1] == 'h') is_risky = 1;
    if (comm[0] == 'n' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e') is_risky = 1;
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h') is_risky = 1;

    // If it's a host daemon, ignore it completely
    if (!is_risky) {
        return 0; 
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *filename = BPF_CORE_READ(dentry, d_name.name);

    char local_name[64] = {0};
    bpf_probe_read_kernel_str(&local_name, sizeof(local_name), filename);

    bpf_printk("[SHADOW-LSM] Program '%s' trying to read: %s\n", comm, local_name);

    int block_execution = 0;
    if (local_name[0] == 'p' && local_name[1] == 'a' &&
        local_name[2] == 's' && local_name[3] == 's' &&
        local_name[4] == 'w' && local_name[5] == 'd') {
        block_execution = 1;
    }

    if (block_execution) {
        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->type = 2; // EVENT_TYPE_FILE
            e->pid = pid;
            __builtin_memcpy(e->filename, local_name, sizeof(local_name));
            bpf_ringbuf_submit(e, 0);
        }
        return -EPERM; 
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";