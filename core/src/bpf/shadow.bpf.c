#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Standard Linux error code for "Permission Denied"
#define EPERM 1 

// Event Type Definitions
#define EVENT_TYPE_EXEC    0
#define EVENT_TYPE_NETWORK 1
#define EVENT_TYPE_FILE    2

// The shared memory structure
struct event_t {
    u32 type;
    u32 pid;
    u32 ppid;
    char filename[256];
};

// The eBPF Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

//THE EXECVE HOOK (Process Tree & Hydra Catching)
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_EXEC;
    e->pid = pid;
    e->ppid = ppid;
    
    const char *prog_name = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), prog_name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

//THE NETWORK HOOK (Socket Monitoring)
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_NETWORK;
    e->pid = pid;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//THE LSM FILE HOOK (Ring 0 Blocking)
SEC("lsm/file_open")
int BPF_PROG(restrict_files, struct file *file) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *filename = BPF_CORE_READ(dentry, d_name.name);

    char local_name[64] = {0}; 
    bpf_probe_read_kernel_str(&local_name, sizeof(local_name), filename);

    //Evaluate the threat locally
    int block_execution = 0;
    
    if (local_name[0] == 'p' && local_name[1] == 'a' && 
        local_name[2] == 's' && local_name[3] == 's' && 
        local_name[4] == 'w' && local_name[5] == 'd') {
        block_execution = 1;
    }

    if (local_name[0] == 'i' && local_name[1] == 'd' && 
        local_name[2] == '_' && local_name[3] == 'r' && 
        local_name[4] == 's' && local_name[5] == 'a') {
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