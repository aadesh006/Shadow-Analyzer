#include "../include/sandbox.h"
#include <iostream>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <sys/mount.h>

// Allocate 1MB for the child process stack
const int STACK_SIZE = 1024 * 1024; 

// A struct to pass arguments from the parent to the sandboxed child
struct ChildArgs {
    const char* command;
    char** argv;
};

Sandbox::Sandbox() {
    //initialize cgroups here to limit CPU/Memory
}

Sandbox::~Sandbox() {}

//RUNS INSIDE THE SANDBOX
int Sandbox::child_entry(void* arg) {
    ChildArgs* args = static_cast<ChildArgs*>(arg);
    
    std::cout << "[Sandbox] Child process alive. Internal PID: " << getpid() << std::endl;
    
    // Mark the root filesystem as PRIVATE for this namespace.
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to make mounts private: " << strerror(errno) << std::endl;
        return -1;
    }

    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        std::cerr << "[Sandbox] Failed to mount isolated /proc: " << strerror(errno) << std::endl;
        return -1;
    }

    //Execute the target program
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
    int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | SIGCHLD;
    
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