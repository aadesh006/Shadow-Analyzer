#include <iostream>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../include/sandbox.h"

const int STACK_SIZE = 1024 * 1024; 

struct ChildArgs {
    const char* command;
    char** argv;
};

// Forward Declaration
bool construct_prison();

Sandbox::Sandbox() {}
Sandbox::~Sandbox() {}

// RUNS INSIDE THE SANDBOX
int Sandbox::child_entry(void* arg) {
    ChildArgs* args = static_cast<ChildArgs*>(arg);

    std::cout << "  [Prison] Constructing pivot_root filesystem isolation..." << std::endl;
    if (!construct_prison()) {
        std::cerr << "  [Prison] FATAL: Failed to construct isolation. Aborting." << std::endl;
        return -1; 
    }
    std::cout << "  [Prison] Host filesystem amputated successfully." << std::endl;
    
    std::cout << "[Sandbox] Child process alive. Internal PID: " << getpid() << std::endl;

    // Failsafe: Ensure the target directories exist
    mkdir("/proc", 0755);
    mkdir("/tmp", 0777);

    // Mount the core filesystems
    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to mount isolated /proc: " << strerror(errno) << std::endl;
        return -1;
    }

    if (mount("tmpfs", "/tmp", "tmpfs", 0, "size=500m,mode=777") == -1) {
        std::cerr << "[Sandbox] Failed to mount tmpfs: " << strerror(errno) << std::endl;
        return -1;
    }

    if (chdir("/tmp") == -1) {
        std::cerr << "[Sandbox] Failed to chdir to /tmp: " << strerror(errno) << std::endl;
        return -1;
    }

    // Forcefully restrict the PATH to standard Linux native directories.
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/tmp", 1);

    if (execvp(args->argv[0], args->argv) == -1) {
        std::cerr << "[Sandbox] execvp failed: " << strerror(errno) << std::endl;
        return -1;
    }
    
    return 0; 
}

int Sandbox::run(const std::string& command, const std::vector<std::string>& args) {
    char* stack = new char[STACK_SIZE];
    char* stack_top = stack + STACK_SIZE;

    std::vector<char*> c_args;
    c_args.push_back(const_cast<char*>("strace"));
    c_args.push_back(const_cast<char*>("-f"));
    c_args.push_back(const_cast<char*>("-ff")); 
    c_args.push_back(const_cast<char*>("-e"));
    c_args.push_back(const_cast<char*>("trace=execve,openat,connect"));
    c_args.push_back(const_cast<char*>("-o"));
    c_args.push_back(const_cast<char*>("shadow_trace.log"));
    c_args.push_back(const_cast<char*>(command.c_str()));
    
    for (const auto& arg : args) {
        c_args.push_back(const_cast<char*>(arg.c_str()));
    }
    c_args.push_back(nullptr); 

    ChildArgs child_args = { command.c_str(), c_args.data() };

    std::cout << "[Shadow] Spawning isolated namespaces" << std::endl;

    // The Isolation Flags
    int flags = SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER; 
    
    pid_t child_pid = clone(child_entry, stack_top, flags, &child_args);

    if (child_pid == -1) {
        std::cerr << "[Shadow] clone() failed! Error: " << strerror(errno) << std::endl;
        delete[] stack;
        return -1;
    }

    std::cout << "[Shadow] Sandbox created. Host mapped PID: " << child_pid << std::endl;

    int status;
    waitpid(child_pid, &status, 0);

    std::cout << "[Shadow] Sandbox execution completed." << std::endl;

    delete[] stack;
    return WEXITSTATUS(status);
}

bool construct_prison() {
    //Destroy broken mounts from previous runs
    system("umount -R /tmp/shadow_jail 2>/dev/null");
    system("rm -rf /tmp/shadow_jail");

    //Ensure mount events in this namespace don't leak back to the host
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to make mounts private." << std::endl;
        return false;
    }

    //Create the staging ground
    const char* jail_dir = "/tmp/shadow_jail";
    mkdir(jail_dir, 0777);

    if (mount(jail_dir, jail_dir, "bind", MS_BIND | MS_REC, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to bind mount jail." << std::endl;
        return false;
    }

    std::vector<std::string> sys_dirs = {
        "/bin", "/sbin", "/usr", "/lib", "/lib64", 
        "/etc", "/dev", "/proc", "/tmp", "/home"
    };
    
    for (const auto& dir : sys_dirs) {
        std::string target = std::string(jail_dir) + dir;
        mkdir(target.c_str(), 0755);
    }

    // Read-Only Host Binds
    std::vector<std::string> ro_binds = {
        "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev"
    };
    
    for (const auto& dir : ro_binds) {
        std::string target = std::string(jail_dir) + dir;
        if (access(dir.c_str(), F_OK) == 0) { // Only mount if the host directory actually exists
            mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REC, NULL);
            mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }
    }

    //THE WORKSPACE (Read-Write Bind)
    std::string home_target = std::string(jail_dir) + "/home";
    mount("/home", home_target.c_str(), "bind", MS_BIND | MS_REC, NULL);

    //THE PIVOT: Swap the entire universe
    const char* put_old = "/tmp/shadow_jail/old_root";
    mkdir(put_old, 0777);
    
    if (syscall(SYS_pivot_root, jail_dir, put_old) == -1) {
        std::cerr << "[Sandbox] pivot_root failed!" << std::endl;
        return false;
    }

    chdir("/");

    //Unmount the host OS 
    if (umount2("/old_root", MNT_DETACH) == -1) {
        std::cerr << "[Sandbox] Failed to unmount host OS." << std::endl;
        return false;
    }
    rmdir("/old_root");

    return true;
}