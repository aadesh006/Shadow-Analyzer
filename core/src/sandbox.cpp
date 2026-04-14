#include "../include/sandbox.h"
#include <iostream>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <vector>

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
    
    // execvp replaces our C++ thread with the target program (e.g., 'npm' or 'sh')
    if (execvp(args->command, args->argv) == -1) {
        std::cerr << "[Sandbox] execvp failed: " << strerror(errno) << std::endl;
        return -1;
    }
    
    return 0; //if execvp fails
}