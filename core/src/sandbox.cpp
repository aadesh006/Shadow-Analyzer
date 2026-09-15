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
#include <dirent.h>
#include <ftw.h>
#include "../include/sandbox.h"

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"

const int STACK_SIZE = 1024 * 1024;

// Host-side paths for OverlayFS layers.
// These are created on the host before clone() so they exist in the mount
// namespace the child inherits before pivot_root severs the old root.
static const char* OVERLAY_BASE  = "/tmp/shadow_overlay";
static const char* OVERLAY_LOWER = "/tmp/shadow_overlay/lower";  // empty read-only base
static const char* OVERLAY_UPPER = "/tmp/shadow_overlay/upper";  // captures all writes
static const char* OVERLAY_WORK  = "/tmp/shadow_overlay/work";   // required by overlayfs
static const char* OVERLAY_MERGE = "/tmp/shadow_overlay/merge";  // the merged /tmp mount point

struct ChildArgs {
    const char* command;
    char** argv;
};

bool construct_prison(const char *target_path);

Sandbox::Sandbox() {}
Sandbox::~Sandbox() {}

// ---------------------------------------------------------------------------
// setup_overlay_dirs()
//
// Creates the four OverlayFS directories on the host side.
// Called from Sandbox::run() (host process, before clone()) so the dirs are
// visible inside the child's mount namespace before pivot_root fires.
// Returns true on success.
// ---------------------------------------------------------------------------
static bool setup_overlay_dirs() {
    // Unmount any previous overlay merge first
    umount2(OVERLAY_MERGE, MNT_DETACH);

    // Wipe upper and work dirs completely — stale content from a previous run
    // causes npm to see packages as already installed and skip preinstall hooks.
    // We use nftw via system() here for simplicity since this runs on the host
    // before clone(), not inside the sandbox.
    if (access(OVERLAY_UPPER, F_OK) == 0) {
        // Remove everything inside upper but keep the dir itself
        DIR* d = opendir(OVERLAY_UPPER);
        if (d) {
            struct dirent* ent;
            while ((ent = readdir(d)) != nullptr) {
                std::string name(ent->d_name);
                if (name == "." || name == "..") continue;
                std::string full = std::string(OVERLAY_UPPER) + "/" + name;
                // Use shell rm -rf to handle nested dirs without needing nftw
                std::string cmd = "rm -rf '" + full + "'";
                system(cmd.c_str());
            }
            closedir(d);
        }
    }

    if (access(OVERLAY_WORK, F_OK) == 0) {
        DIR* d = opendir(OVERLAY_WORK);
        if (d) {
            struct dirent* ent;
            while ((ent = readdir(d)) != nullptr) {
                std::string name(ent->d_name);
                if (name == "." || name == "..") continue;
                std::string full = std::string(OVERLAY_WORK) + "/" + name;
                std::string cmd = "rm -rf '" + full + "'";
                system(cmd.c_str());
            }
            closedir(d);
        }
    }

    // Create dirs (no-op if already exist)
    mkdir(OVERLAY_BASE,  0700);
    mkdir(OVERLAY_LOWER, 0700);
    mkdir(OVERLAY_UPPER, 0700);
    mkdir(OVERLAY_WORK,  0700);
    mkdir(OVERLAY_MERGE, 0700);

    // Mount OverlayFS: lower=empty dir, upper captures writes, merge is the view
    std::string opts = std::string("lowerdir=")  + OVERLAY_LOWER +
                       ",upperdir="  + OVERLAY_UPPER +
                       ",workdir="   + OVERLAY_WORK;

    if (mount("overlay", OVERLAY_MERGE, "overlay", 0, opts.c_str()) != 0) {
        std::cerr << COLOR_YELLOW
                  << "[Shadow] OverlayFS setup failed — filesystem diff unavailable. "
                  << "Analysis will proceed without shadow diff."
                  << COLOR_RESET << std::endl;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// construct_prison()
//
// Called from inside the child namespace after pivot_root.
// Builds the read-only bind-mount tree under /tmp/shadow_jail, mounts
// the OverlayFS merge dir as /tmp (so all package writes land in upper),
// then pivots root into the jail.
// ---------------------------------------------------------------------------
bool construct_prison(const char *target_path) {
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) return false;

    const char* jail_dir = "/tmp/shadow_jail";
    mkdir(jail_dir, 0777);
    if (mount(jail_dir, jail_dir, "bind", MS_BIND | MS_REC, NULL) == -1) return false;

    std::vector<std::string> sys_dirs = {
        "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc",
        "/dev", "/proc", "/tmp", "/home", "/run"
    };
    for (const auto& dir : sys_dirs) {
        mkdir((std::string(jail_dir) + dir).c_str(), 0755);
    }

    std::vector<std::string> ro_binds = {
        "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/run"
    };
    for (const auto& dir : ro_binds) {
        std::string target = std::string(jail_dir) + dir;
        if (access(dir.c_str(), F_OK) == 0) {
            mount(dir.c_str(), target.c_str(), "bind", MS_BIND | MS_REC, NULL);
            mount(dir.c_str(), target.c_str(), "bind",
                  MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        }
    }

    std::string home_target = std::string(jail_dir) + "/home";
    if (access("/home", F_OK) == 0) {
        mount("/home", home_target.c_str(), "bind", MS_BIND | MS_REC, NULL);
        mount("/home", home_target.c_str(), "bind",
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
    }

    mount("proc", (std::string(jail_dir) + "/proc").c_str(), "proc", 0, NULL);

    // Mount /tmp — prefer the OverlayFS merge point so writes are tracked.
    // Fall back to a plain tmpfs if OverlayFS setup failed on the host side.
    std::string tmp_target = std::string(jail_dir) + "/tmp";
    if (access(OVERLAY_MERGE, F_OK) == 0) {
        if (mount(OVERLAY_MERGE, tmp_target.c_str(), "bind", MS_BIND | MS_REC, NULL) == 0) {
            std::cout << "  [Prison] OverlayFS /tmp mounted — filesystem diff active." << std::endl;
        } else {
            // Bind failed (e.g. overlayfs not mounted) — fall back to tmpfs
            mount("tmpfs", tmp_target.c_str(), "tmpfs", 0, "size=500m,mode=777");
        }
    } else {
        mount("tmpfs", tmp_target.c_str(), "tmpfs", 0, "size=500m,mode=777");
    }

    const char* put_old = "/tmp/shadow_jail/old_root";
    mkdir(put_old, 0777);
    if (syscall(SYS_pivot_root, jail_dir, put_old) == -1) return false;

    chdir("/");

    // Copy tarball into the jail's /tmp if the target is a local file path
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
            std::cout << "  [Prison] ERROR: Failed to stage " << src << std::endl;
        }
    }

    umount2("/old_root", MNT_DETACH);
    rmdir("/old_root");

    return true;
}

// ---------------------------------------------------------------------------
// CHILD EXECUTION
// ---------------------------------------------------------------------------
int Sandbox::child_entry(void* arg) {
    ChildArgs* args = static_cast<ChildArgs*>(arg);

    std::cout << "  [Prison] Sandbox Paused. Awaiting identity injection from Host..." << std::endl;
    sleep(1);

    if (!construct_prison(args->argv[2])) return -1;

    std::cout << "  [Prison] Host filesystem amputated successfully." << std::endl;

    const char* sudo_uid = getenv("SUDO_UID");
    const char* sudo_gid = getenv("SUDO_GID");
    int target_uid = sudo_uid ? atoi(sudo_uid) : 1000;
    int target_gid = sudo_gid ? atoi(sudo_gid) : 1000;

    chown("/tmp", target_uid, target_gid);

    // Use a dedicated install subdir so npm always sees a fresh empty project.
    // Running from /tmp directly caused "up to date" because OverlayFS persists
    // package.json from the previous run in the upper layer.
    const char* install_dir = "/tmp/sandbox_pkg";
    mkdir(install_dir, 0755);
    chown(install_dir, target_uid, target_gid);

    // Create package.json while still root so npm executes postinstall hooks
    const char* ctx = "{\"name\":\"shadow-sandbox\",\"version\":\"1.0.0\"}\n";
    std::string pkg_json_path = std::string(install_dir) + "/package.json";
    int pfd = open(pkg_json_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pfd >= 0) {
        write(pfd, ctx, strlen(ctx));
        close(pfd);
        chown(pkg_json_path.c_str(), target_uid, target_gid);
        std::cout << "  [Prison] Sandbox context created." << std::endl;
    }

    // Drop privileges
    setgid(target_gid);
    setuid(target_uid);

    std::cout << "  [Prison] Sandbox identity downgraded to UID: " << getuid() << std::endl;

    if (chdir(install_dir) == -1) return -1;

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

// ---------------------------------------------------------------------------
// ENGINE LAUNCHER
// ---------------------------------------------------------------------------
int Sandbox::run(const std::string& command, const std::vector<std::string>& args,
                 std::function<void(pid_t)> on_spawn) {

    // Clean up any previous jail
    umount2("/tmp/shadow_jail", MNT_DETACH);

    // Set up OverlayFS dirs on the host before spawning the child.
    // The child inherits these paths in its mount namespace.
    bool overlay_ok = setup_overlay_dirs();
    if (overlay_ok) {
        overlay_upper_dir = OVERLAY_UPPER;
    }

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

    // Write UID/GID maps to complete CLONE_NEWUSER setup
    const char* sudo_uid = getenv("SUDO_UID");
    const char* sudo_gid = getenv("SUDO_GID");
    std::string uid_str = sudo_uid ? sudo_uid : "1000";
    std::string gid_str = sudo_gid ? sudo_gid : "1000";

    std::string uid_map = "0 0 1\n" + uid_str + " " + uid_str + " 1\n";
    std::string gid_map = "0 0 1\n" + gid_str + " " + gid_str + " 1\n";

    char path[256];

    snprintf(path, sizeof(path), "/proc/%d/uid_map", child_pid);
    int fd = open(path, O_WRONLY);
    if (fd >= 0) { write(fd, uid_map.c_str(), uid_map.size()); close(fd); }

    snprintf(path, sizeof(path), "/proc/%d/setgroups", child_pid);
    fd = open(path, O_WRONLY);
    if (fd >= 0) { write(fd, "deny", 4); close(fd); }

    snprintf(path, sizeof(path), "/proc/%d/gid_map", child_pid);
    fd = open(path, O_WRONLY);
    if (fd >= 0) { write(fd, gid_map.c_str(), gid_map.size()); close(fd); }

    // Wait for sandbox to finish, with 60s timeout
    int status;
    int timeout_secs = 60;
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
                delete[] stack;
                return 124;
            }
            usleep(100000);
        }
    }

    std::cout << "[Shadow] Sandbox execution completed." << std::endl;

    delete[] stack;
    return WEXITSTATUS(status);
}
