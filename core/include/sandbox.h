#pragma once

#include <string>
#include <vector>
#include <functional>

class Sandbox {
public:
    Sandbox();
    ~Sandbox();

    int run(const std::string& command, const std::vector<std::string>& args,
        std::function<void(pid_t)> on_spawn = nullptr);

private:
    static int child_entry(void* args);
};