#include "../include/sandbox.h"
#include <iostream>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

// Allocate 1MB for the child process stack
const int STACK_SIZE = 1024 * 1024; 

bool construct_prison();
void setup_user_mapping();

// A struct to pass arguments from the parent to the sandboxed child
struct ChildArgs {
    const char* command;
    char** argv;
};

Sandbox::Sandbox() {
    //initialize cgroups here to limit CPU/Memory
}

Sandbox::~Sandbox() {}

void setup_user_mapping() {
    int fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd != -1) {
        write(fd, "0 0 1\n", 6);
        close(fd);
    }
    
    int fd_setgroups = open("/proc/self/setgroups", O_WRONLY);
    if (fd_setgroups != -1) {
        write(fd_setgroups, "deny", 4);
        close(fd_setgroups);
    }

    int fd_gid = open("/proc/self/gid_map", O_WRONLY);
    if (fd_gid != -1) {
        write(fd_gid, "0 0 1\n", 6);
        close(fd_gid);
    }
}

//RUNS INSIDE THE SANDBOX
int Sandbox::child_entry(void* arg) {
    ChildArgs* args = static_cast<ChildArgs*>(arg);

    std::cout << "  [Prison] Constructing pivot_root filesystem isolation..." << std::endl;
    if (!construct_prison()) {
        std::cerr << "  [Prison] FATAL: Failed to construct isolation. Aborting." << std::endl;
        return -1; // Never execute malware if the cage is broken!
    }
    std::cout << "  [Prison] Host filesystem amputated successfully." << std::endl;
    
    std::cout << "[Sandbox] Child process alive. Internal PID: " << getpid() << std::endl;
    
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to make mounts private: " << strerror(errno) << std::endl;
        return -1;
    }

    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to mount isolated /proc: " << strerror(errno) << std::endl;
        return -1;
    }

    // The RAM-Disk: Mount tmpfs over /tmp to intercept file writes
    if (mount("tmpfs", "/tmp", "tmpfs", 0, "size=500m,mode=777") == -1) {
        std::cerr << "[Sandbox] Failed to mount tmpfs: " << strerror(errno) << std::endl;
        return -1;
    }

    if (chdir("/tmp") == -1) {
        std::cerr << "[Sandbox] Failed to chdir to /tmp: " << strerror(errno) << std::endl;
        return -1;
    }

    //forcefully restrict the PATH to standard Linux native directories.
   setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
   
   setenv("HOME", "/tmp", 1);//Force npm to believe its home directory is our RAM disk

    if (execvp(args->argv[0], args->argv) == -1) {
        std::cerr << "[Sandbox] execvp failed: " << strerror(errno) << std::endl;
        return -1;
    }
    
    return 0; 
}

int Sandbox::run(const std::string& command, const std::vector<std::string>& args) {
    char* stack = new char[STACK_SIZE];
    
    // On x86/ARM architectures, stacks grow downwards in memory. 
    // So we must pass the TOP of the allocated memory block to clone().
    char* stack_top = stack + STACK_SIZE;

    // Format arguments for standard C-style execvp
    std::vector<char*> c_args;
    
    c_args.push_back(const_cast<char*>("strace"));
    c_args.push_back(const_cast<char*>("-f"));
    c_args.push_back(const_cast<char*>("-ff")); //fix for strace multithreading bug
    c_args.push_back(const_cast<char*>("-e"));
    c_args.push_back(const_cast<char*>("trace=execve,openat,connect"));
    c_args.push_back(const_cast<char*>("-o"));
    c_args.push_back(const_cast<char*>("shadow_trace.log"));
    
    //append the actual target command (e.g., 'sh' or 'npm')
    c_args.push_back(const_cast<char*>(command.c_str()));
    for (const auto& arg : args) {
        c_args.push_back(const_cast<char*>(arg.c_str()));
    }
    c_args.push_back(nullptr); // Must be null-terminated

    ChildArgs child_args = { command.c_str(), c_args.data() };

    std::cout << "[Shadow] Spawning isolated namespaces" << std::endl;

    //The Isolation Logic
    int flags = SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER; //removed CLONE_NEWNET temporarily
    
    pid_t child_pid = clone(child_entry, stack_top, flags, &child_args);

    if (child_pid == -1) {
        std::cerr << "[Shadow] clone() failed! Are you running as root? Error: " << strerror(errno) << std::endl;
        delete[] stack;
        return -1;
    }

    std::cout << "[Shadow] Sandbox created. Host mapped PID: " << child_pid << std::endl;

    //Wait for the sandbox to finish its execution
    int status;
    waitpid(child_pid, &status, 0);

    std::cout << "[Shadow] Sandbox execution completed." << std::endl;

    delete[] stack;
    return WEXITSTATUS(status);
}

bool construct_prison() {
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to make mounts private." << std::endl;
        return false;
    }

    const char* jail_dir = "/tmp/shadow_jail";
    mkdir(jail_dir, 0777);
    if (mount(jail_dir, jail_dir, "bind", MS_BIND | MS_REC, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to bind mount jail." << std::endl;
        return false;
    }

    // Create the physical directories before mounting to them
    std::vector<std::string> sys_dirs = {
        "/bin", "/sbin", "/usr", "/lib", "/lib64", 
        "/etc", "/dev", "/proc", "/tmp", "/home"
    };
    
    for (const auto& dir : sys_dirs) {
        std::string target = std::string(jail_dir) + dir;
        mkdir(target.c_str(), 0755);
    }

    // Port the host OS tools into the jail, but strictly read-only
    std::vector<std::string> ro_binds = {
        "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev"
    };
    
    for (const auto& dir : ro_binds) {
        std::string target = std::string(jail_dir) + dir;
        mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REC, NULL);
        // Lock the door: Remount strictly as Read-Only
        mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
    }

    // NPM needs to access /home/aadesh/Desktop/dummy_pkg
    std::string home_target = std::string(jail_dir) + "/home";
    mount("/home", home_target.c_str(), "bind", MS_BIND | MS_REC, NULL);

    // --- 4. THE PIVOT (Locking the Door) ---
    const char* put_old = "/tmp/shadow_jail/old_root";
    mkdir(put_old, 0777);
    
    if (syscall(SYS_pivot_root, jail_dir, put_old) == -1) {
        std::cerr << "[Sandbox] pivot_root failed!" << std::endl;
        return false;
    }

    chdir("/");

    if (umount2("/old_root", MNT_DETACH) == -1) {
        std::cerr << "[Sandbox] Failed to unmount host OS." << std::endl;
        return false;
    }
    rmdir("/old_root");

    return true;
}