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

bool construct_prison();
bool setup_user_mapping();

Sandbox::Sandbox() {}
Sandbox::~Sandbox() {}

bool setup_user_mapping() {
    std::cout << "  [Prison] Negotiating namespace identities with host kernel..." << std::endl;
    
    // Retrieve the real user's ID who executed 'sudo'
    const char* sudo_uid = getenv("SUDO_UID");
    const char* sudo_gid = getenv("SUDO_GID");
    
    std::string uid_str = sudo_uid ? sudo_uid : "0";
    std::string gid_str = sudo_gid ? sudo_gid : "0";
    
    // Map Sandbox UID 0 -> Host User UID
    std::string uid_map = "0 " + uid_str + " 1\n";
    std::string gid_map = "0 " + gid_str + " 1\n";

    int fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd == -1) return false;
    write(fd, uid_map.c_str(), uid_map.length());
    close(fd);

    int fd_setgroups = open("/proc/self/setgroups", O_WRONLY);
    if (fd_setgroups != -1) { write(fd_setgroups, "deny", 4); close(fd_setgroups); }

    int fd_gid = open("/proc/self/gid_map", O_WRONLY);
    if (fd_gid == -1) return false;
    write(fd_gid, gid_map.c_str(), gid_map.length());
    close(fd_gid);

    std::cout << "  [Prison] Sandbox Root mapped securely to Host UID: " << uid_str << std::endl;
    return true;
}


bool construct_prison() {
    system("umount -R /tmp/shadow_jail 2>/dev/null");
    system("rm -rf /tmp/shadow_jail");

    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) return false;

    const char* jail_dir = "/tmp/shadow_jail";
    mkdir(jail_dir, 0777);
    if (mount(jail_dir, jail_dir, "bind", MS_BIND | MS_REC, NULL) == -1) return false;

    std::vector<std::string> sys_dirs = {"/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/tmp", "/home"};
    for (const auto& dir : sys_dirs) {
        std::string target = std::string(jail_dir) + dir;
        mkdir(target.c_str(), 0755);
    }

    std::vector<std::string> ro_binds = {"/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev"};
    for (const auto& dir : ro_binds) {
        std::string target = std::string(jail_dir) + dir;
        if (access(dir.c_str(), F_OK) == 0) { 
            mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REC, NULL);
            mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }
    }

    std::string home_target = std::string(jail_dir) + "/home";
    mount("/home", home_target.c_str(), "bind", MS_BIND | MS_REC, NULL);

    // FIX: Mount proc and tmp BEFORE pivot!
    std::string proc_target = std::string(jail_dir) + "/proc";
    mount("proc", proc_target.c_str(), "proc", 0, NULL);
    
    std::string tmp_target = std::string(jail_dir) + "/tmp";
    mount("tmpfs", tmp_target.c_str(), "tmpfs", 0, "size=500m,mode=777");

    // THE PIVOT
    const char* put_old = "/tmp/shadow_jail/old_root";
    mkdir(put_old, 0777);
    if (syscall(SYS_pivot_root, jail_dir, put_old) == -1) return false;

    chdir("/");

    if (umount2("/old_root", MNT_DETACH) == -1) return false;
    rmdir("/old_root");

    return true;
}

//CHILD EXECUTION
int Sandbox::child_entry(void* arg) {
    if (!setup_user_mapping()) return -1;

    ChildArgs* args = static_cast<ChildArgs*>(arg);
    std::cout << "  [Prison] Constructing pivot_root filesystem isolation..." << std::endl;
    

    if (!construct_prison()) {
        std::cerr << "  [Prison] FATAL: Failed to construct isolation." << std::endl;
        return -1; 
    }
    
    std::cout << "  [Prison] Host filesystem amputated successfully." << std::endl;
    std::cout << "[Sandbox] Child process alive. Internal PID: " << getpid() << std::endl;

    // Move into the workspace
    if (chdir("/tmp") == -1) return -1;

    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/tmp", 1);

    if (execvp(args->argv[0], args->argv) == -1) {
        std::cerr << "[Sandbox] execvp failed: " << strerror(errno) << std::endl;
        return -1;
    }
    return 0; 
}

//ENGINE LAUNCHER
int Sandbox::run(const std::string& command, const std::vector<std::string>& args) {
    char* stack = new char[STACK_SIZE];
    char* stack_top = stack + STACK_SIZE;

    std::vector<char*> c_args;
    
    c_args.push_back(const_cast<char*>(command.c_str()));
    for (const auto& arg : args) {
        c_args.push_back(const_cast<char*>(arg.c_str()));
    }
    c_args.push_back(nullptr); 

    ChildArgs child_args = { command.c_str(), c_args.data() };
    std::cout << "[Shadow] Spawning isolated namespaces" << std::endl;

    int flags = SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER; 
    pid_t child_pid = clone(child_entry, stack_top, flags, &child_args);

    if (child_pid == -1) { delete[] stack; return -1; }
    std::cout << "[Shadow] Sandbox created. Host mapped PID: " << child_pid << std::endl;

    int status;
    waitpid(child_pid, &status, 0);
    
    std::cout << "[Shadow] Sandbox execution completed." << std::endl;

    delete[] stack;
    return WEXITSTATUS(status);
}