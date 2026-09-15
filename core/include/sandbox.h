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

    // Path on the host where OverlayFS upper dir lives after the sandbox exits.
    // Contains every file the package created or modified during install.
    // Empty string if OverlayFS setup failed (analysis still proceeds normally).
    std::string overlay_upper_dir;

private:
    static int child_entry(void* args);
};