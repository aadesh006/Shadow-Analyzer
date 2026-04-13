#pragma once

#include <string>
#include <vector>

class Sandbox {
public:
    Sandbox();
    ~Sandbox();

    int run(const std::string& command, const std::vector<std::string>& args);

private:
    static int child_entry(void* args);
};