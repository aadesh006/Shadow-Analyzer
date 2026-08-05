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
#include <fstream>
#include "../include/sandbox.h"

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"

const int STACK_SIZE = 1024 * 1024; 

struct ChildArgs {
    const char* command;
    char** argv;
};

bool construct_prison(const char *target_path);

Sandbox::Sandbox() {}
Sandbox::~Sandbox() {}


bool construct_prison(const char *target_path) {
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) return false;
    const char* jail_dir = "/tmp/shadow_jail";
    
    mkdir(jail_dir, 0777);
    if (mount(jail_dir, jail_dir, "bind", MS_BIND | MS_REC, NULL) == -1) return false;


    std::vector<std::string> sys_dirs = {
        "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/tmp", "/home", "/run" 
    };

    for (const auto& dir : sys_dirs) {
        std::string target = std::string(jail_dir) + dir;
        mkdir(target.c_str(), 0755);
    }

    std::vector<std::string> ro_binds = {
        "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/run"
    };
    
    for (const auto& dir : ro_binds) {
        std::string target = std::string(jail_dir) + dir;
        if (access(dir.c_str(), F_OK) == 0) { 
            mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REC, NULL);
            mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }
    }

    std::string home_target = std::string(jail_dir) + "/home";

    if (access("/home", F_OK) == 0) {
        mount("/home", home_target.c_str(), "bind", MS_BIND | MS_REC, NULL);
        mount("/home", home_target.c_str(), "bind", 
          MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
    }

    std::string proc_target = std::string(jail_dir) + "/proc";
    mount("proc", proc_target.c_str(), "proc", 0, NULL);
    
    std::string tmp_target = std::string(jail_dir) + "/tmp";
    mount("tmpfs", tmp_target.c_str(), "tmpfs", 0, "size=500m,mode=777");

    const char* put_old = "/tmp/shadow_jail/old_root";
    mkdir(put_old, 0777);
    if (syscall(SYS_pivot_root, jail_dir, put_old) == -1) return false;

    chdir("/");

// Copy ANY target file into the jail's /tmp
    if (target_path != nullptr && target_path[0] == '/') {
        std::string filename = std::string(target_path);
        filename = filename.substr(filename.find_last_of('/') + 1);

        std::string src = std::string("/old_root") + target_path;
        std::string dst = "/tmp/" + filename;

        std::ifstream in(src, std::ios::binary);
        std::ofstream out(dst, std::ios::binary);
        
        if (in && out) {
            out << in.rdbuf();
            chmod(dst.c_str(), 0644);
            std::cout << "  [Prison] Tarball staged natively: " << dst << std::endl;
        } else {
            std::cout << "  [Prison] ERROR: Failed to read from " << src << " or write to " << dst << std::endl;
        }
    }

    umount2("/old_root", MNT_DETACH);
    rmdir("/old_root");

    return true;
}

//CHILD EXECUTION
int Sandbox::child_entry(void* arg) {
    ChildArgs* args = static_cast<ChildArgs*>(arg);
    

    std::cout << "  [Prison] Sandbox Paused. Awaiting identity injection from Host..." << std::endl;
    sleep(1);

    // Build the void as Root, passing the target path
    if (!construct_prison(args->argv[2])) return -1;
    
    std::cout << "  [Prison] Host filesystem amputated successfully." << std::endl;
    if (chdir("/tmp") == -1) return -1;

// THE SECURE DOWNGRADE
const char* sudo_uid = getenv("SUDO_UID");
const char* sudo_gid = getenv("SUDO_GID");
int target_uid = sudo_uid ? atoi(sudo_uid) : 1000;
int target_gid = sudo_gid ? atoi(sudo_gid) : 1000;

chown("/tmp", target_uid, target_gid);

// Create package.json WHILE STILL ROOT so npm runs postinstall
const char* ctx = "{\"name\":\"shadow-sandbox\",\"version\":\"1.0.0\"}\n";
int pfd = open("/tmp/package.json", O_WRONLY | O_CREAT | O_TRUNC, 0644);
if (pfd >= 0) {
    write(pfd, ctx, strlen(ctx));
    close(pfd);
    chown("/tmp/package.json", target_uid, target_gid);
    std::cout << "  [Prison] Sandbox context created." << std::endl;
}

// NOW drop privileges
setgid(target_gid);
setuid(target_uid);


    std::cout << "  [Prison] Sandbox Identity downgraded securely to UID: " << getuid() << std::endl;


    unsetenv("SUDO_UID");
    unsetenv("SUDO_GID");
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/tmp", 1);
    setenv("npm_config_cache", "/tmp/.npm", 1);

    if (execvp(args->argv[0], args->argv) == -1) {
        std::cerr << "[Sandbox] execvp failed: " << strerror(errno) << std::endl;
        return -1;
    }
    return 0; 
}

//ENGINE LAUNCHER
int Sandbox::run(const std::string& command, const std::vector<std::string>& args, std::function<void(pid_t)> on_spawn) {
    
    umount2("/tmp/shadow_jail", MNT_DETACH);

    char* stack = new char[STACK_SIZE];
    char* stack_top = stack + STACK_SIZE;

    std::vector<char*> c_args;
    c_args.push_back(const_cast<char*>(command.c_str()));
    for (const auto& arg : args) c_args.push_back(const_cast<char*>(arg.c_str()));
    c_args.push_back(nullptr); 

    ChildArgs child_args = { command.c_str(), c_args.data() };
    std::cout << "[Shadow] Spawning isolated namespaces" << std::endl;

    int flags = SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER; 
    pid_t child_pid = clone(child_entry, stack_top, flags, &child_args);

    if (child_pid == -1) { delete[] stack; return -1; }
    std::cout << "[Shadow] Sandbox created. Host mapped PID: " << child_pid << std::endl;
    if (on_spawn) on_spawn(child_pid);


    //running as real root
    const char* sudo_uid = getenv("SUDO_UID");
    const char* sudo_gid = getenv("SUDO_GID");
    std::string uid_str = sudo_uid ? sudo_uid : "1000";
    std::string gid_str = sudo_gid ? sudo_gid : "1000";

    // Map Sandbox 0 -> Host 0 AND Sandbox 1000 -> Host 1000
    std::string uid_map = "0 0 1\n" + uid_str + " " + uid_str + " 1\n";
    std::string gid_map = "0 0 1\n" + gid_str + " " + gid_str + " 1\n";

    char path[256];
    
    sprintf(path, "/proc/%d/uid_map", child_pid);
    int fd = open(path, O_WRONLY);
    write(fd, uid_map.c_str(), uid_map.length());
    close(fd);

    sprintf(path, "/proc/%d/setgroups", child_pid);
    fd = open(path, O_WRONLY);
    write(fd, "deny", 4);
    close(fd);

    sprintf(path, "/proc/%d/gid_map", child_pid);
    fd = open(path, O_WRONLY);
    write(fd, gid_map.c_str(), gid_map.length());
    close(fd);

int status;
int timeout_secs = 60; // kill sandbox after 60 seconds
time_t start = time(nullptr);
pid_t result = 0;

while (result == 0) {
    result = waitpid(child_pid, &status, WNOHANG);
    if (result == 0) {
        if (time(nullptr) - start >= timeout_secs) {
            std::cout << COLOR_YELLOW 
                      << "[Shadow] Sandbox timeout — killing analysis."
                      << COLOR_RESET << std::endl;
            kill(child_pid, SIGKILL);
            waitpid(child_pid, &status, 0);
            return 124;
        }
        usleep(100000); // poll every 100ms
    }
}

    std::cout << "[Shadow] Sandbox execution completed." << std::endl;

    delete[] stack;
    return WEXITSTATUS(status);
}
