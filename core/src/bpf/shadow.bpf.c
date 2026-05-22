#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM    1
#define AF_INET  2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

struct event_t {
    u32  type;          // 1=network, 2=lsm_block, 3=process
    u32  pid;
    u32  ppid;
    u32  dest_ip;       // IPv4 destination (network byte order)
    u16  dest_port;     // destination port (host byte order)
    u16  family;        // AF_INET=2
    char filename[256]; // file path or binary path
    char comm[16];      // process name that triggered event
};

//Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


struct path_key {
    char name[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   struct path_key);
    __type(value, u32);             // 1 = block
} blocklist SEC(".maps");


//Process Tracking (execve)
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 3; // PROCESS
    e->pid  = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 3; // PROCESS
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // In execveat, the filename pointer is usually args[1], not args[0]
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

//Network Connection Tracking
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sockaddr sa = {};
    void *uaddr = (void *)ctx->args[1];
    if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) != 0)
        return 0;

    if (sa.sa_family == AF_INET6) {
        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) return 0;
        
        e->type = 1;
        e->pid = pid;
        e->family = AF_INET6; 
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    if (sa.sa_family != AF_INET) return 0;

    struct sockaddr_in sa4 = {};
    if (bpf_probe_read_user(&sa4, sizeof(sa4), uaddr) != 0)
        return 0;

    u16 port = __builtin_bswap16(sa4.sin_port);
    u32 ip   = sa4.sin_addr.s_addr;

    //Noise filters
    // Port 53: DNS queries — including shadow's own resolve_ipv4() calls
    if (port == 0)  return 0;
    if (port == 53) return 0;

    // Loopback: 127.x.x.x — system-internal traffic, never malware C2
    if ((ip & 0xFF) == 127) return 0;

    // Private ranges: 192.168.x.x and 10.x.x.x — local network, not C2
    if ((ip & 0xFFFF) == 0xA8C0) return 0; // 192.168.x.x
    if ((ip & 0xFF)   == 0x0A)   return 0; // 10.x.x.x

    if ((ip & 0xFF) == 0x0A) return 0;

    u8 b1 = ip & 0xFF;
    u8 b2 = (ip >> 8) & 0xFF;
    if (b1 == 0xAC && b2 >= 0x10 && b2 <= 0x1F) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type      = 1;
    e->pid       = pid;
    e->ppid      = 0;
    e->family    = AF_INET;
    e->dest_ip   = ip;
    e->dest_port = port;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(shadow_file_open, struct file *file) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid < 100) return 0;

    struct path_key key = {};
    const unsigned char *fname = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(&key.name, sizeof(key.name), fname);

    u32 *rule = bpf_map_lookup_elem(&blocklist, &key);

    if (rule && *rule == 1) {
        struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->type = 2; // LSM_BLOCK
            e->pid  = pid;
            bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }

        bpf_printk("[SHADOW-LSM] BLOCKED %s by PID %d\n", key.name, pid);

        return -EPERM;
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->type = 4; // MEMFD
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *name_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), name_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}