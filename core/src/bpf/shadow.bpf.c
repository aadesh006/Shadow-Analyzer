#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

// The exact same struct your C++ code expects
struct event_t {
    u32 type;
    u32 pid;
    u32 ppid;
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// --- NEW: THE DYNAMIC BLOCKLIST MAP ---
// We use a fixed-size char array as the key so strings match perfectly.
struct path_key {
    char name[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct path_key); // The filename (e.g., "passwd", "credentials")
    __type(value, u32);           // 1 = Block, 0 = Allow
} blocklist SEC(".maps");


// --- 1. PROCESS TRACKING (EXECVE) ---
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 1; // 1 = Process execution
    e->pid = bpf_get_current_pid_tgid() >> 32;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// --- 2. DYNAMIC LSM BLOCKING ---
SEC("lsm/file_open")
int BPF_PROG(shadow_file_open, struct file *file) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Ignore the host OS (our engine and root processes). Only watch the Sandbox.
    if (pid < 1000) return 0; 

    // Extract the name of the file being opened
    struct path_key key = {};
    bpf_probe_read_kernel_str(&key.name, sizeof(key.name), file->f_path.dentry->d_name.name);

    // DYNAMIC LOOKUP: Does this file exist in our map?
    u32 *rule = bpf_map_lookup_elem(&blocklist, &key);
    
    if (rule && *rule == 1) {
        // Boom. It's in the blocklist.
        bpf_printk("[LSM BLOCK DYNAMIC] Access denied to: %s by PID: %d\n", key.name, pid);
        
        // Optional: Send an alert to C++ via ringbuf here
        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->type = 2; // 2 = Blocked File Access
            e->pid = pid;
            bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), key.name);
            bpf_ringbuf_submit(e, 0);
        }

        return -EPERM; // Return Operation Not Permitted
    }

    return 0;
}