#include "../include/apt_analyzer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"

AptAnalyzer::AptAnalyzer() : is_local_deb(false) {}

AptAnalyzer::~AptAnalyzer() {
    // Don't auto-cleanup — caller controls lifetime so the sandbox
    // can still access the scripts after this object is destroyed.
}

// ---------------------------------------------------------------------------
// fetch()
//
// If package_name_or_path ends with .deb, treat it as a local file path.
// Otherwise use `apt-get download` to fetch from the apt cache.
// Either way, the .deb ends up at work_dir/package.deb.
// ---------------------------------------------------------------------------
bool AptAnalyzer::fetch(const std::string& package_name_or_path) {
    // Build a per-run temp working dir using our PID
    work_dir = "/tmp/shadow_apt_" + std::to_string(getpid());
    mkdir(work_dir.c_str(), 0700);

    // Detect local .deb vs registry package name
    bool looks_like_deb = (package_name_or_path.size() > 4 &&
        package_name_or_path.substr(package_name_or_path.size() - 4) == ".deb");

    if (looks_like_deb) {
        // Local .deb — just use it directly (or copy if outside /tmp)
        is_local_deb = true;

        if (access(package_name_or_path.c_str(), F_OK) != 0) {
            std::cerr << COLOR_RED << "[APT] Local .deb not found: "
                      << package_name_or_path << COLOR_RESET << std::endl;
            return false;
        }

        // Copy to work_dir so we have a clean working copy
        deb_path = work_dir + "/package.deb";
        std::ifstream src(package_name_or_path, std::ios::binary);
        std::ofstream dst(deb_path, std::ios::binary);
        if (!src || !dst) {
            std::cerr << COLOR_RED << "[APT] Failed to copy .deb to work dir."
                      << COLOR_RESET << std::endl;
            return false;
        }
        dst << src.rdbuf();

        // Extract package name and version from the .deb control file
        std::string ctrl_cmd = "dpkg-deb --field '" + deb_path + "' Package 2>/dev/null";
        FILE* f = popen(ctrl_cmd.c_str(), "r");
        if (f) {
            char buf[256] = {};
            if (fgets(buf, sizeof(buf), f)) {
                package_name = std::string(buf);
                // strip trailing newline
                if (!package_name.empty() && package_name.back() == '\n')
                    package_name.pop_back();
            }
            pclose(f);
        }

        std::string ver_cmd = "dpkg-deb --field '" + deb_path + "' Version 2>/dev/null";
        f = popen(ver_cmd.c_str(), "r");
        if (f) {
            char buf[256] = {};
            if (fgets(buf, sizeof(buf), f)) {
                package_version = std::string(buf);
                if (!package_version.empty() && package_version.back() == '\n')
                    package_version.pop_back();
            }
            pclose(f);
        }

        if (package_name.empty()) package_name = package_name_or_path;

        std::cout << COLOR_CYAN << "[APT]" << COLOR_RESET
                  << " Local package: " << package_name
                  << " " << package_version << std::endl;
        return true;
    }

    // Registry package — use apt-get download
    is_local_deb = false;
    package_name = package_name_or_path;

    std::cout << COLOR_CYAN << "[APT]" << COLOR_RESET
              << " Fetching " << package_name << " from apt cache..." << std::endl;

    // apt-get download writes the .deb into the current directory
    // Run it from work_dir so the file lands there
    std::string dl_cmd = "cd '" + work_dir + "' && apt-get download '" +
                         package_name + "' 2>&1";

    FILE* f = popen(dl_cmd.c_str(), "r");
    if (!f) {
        std::cerr << COLOR_RED << "[APT] Failed to run apt-get download."
                  << COLOR_RESET << std::endl;
        return false;
    }

    char buf[512];
    std::string output;
    while (fgets(buf, sizeof(buf), f)) output += buf;
    int rc = pclose(f);

    if (rc != 0) {
        std::cerr << COLOR_RED << "[APT] apt-get download failed:\n"
                  << output << COLOR_RESET << std::endl;
        return false;
    }

    // Find the downloaded .deb — apt-get names it <pkg>_<ver>_<arch>.deb
    DIR* d = opendir(work_dir.c_str());
    if (!d) return false;

    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        std::string name(ent->d_name);
        if (name.size() > 4 && name.substr(name.size() - 4) == ".deb") {
            deb_path = work_dir + "/" + name;

            // Extract version from filename: name_version_arch.deb
            size_t first_us = name.find('_');
            size_t second_us = name.find('_', first_us + 1);
            if (first_us != std::string::npos && second_us != std::string::npos) {
                package_version = name.substr(first_us + 1, second_us - first_us - 1);
            }
            break;
        }
    }
    closedir(d);

    if (deb_path.empty()) {
        std::cerr << COLOR_RED << "[APT] No .deb found after download."
                  << COLOR_RESET << std::endl;
        return false;
    }

    std::cout << COLOR_CYAN << "[APT]" << COLOR_RESET
              << " Downloaded: " << deb_path << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// extract_scripts()
//
// Runs dpkg-deb --control to extract the DEBIAN/ directory from the .deb.
// Returns paths to all maintainer scripts that exist and are non-empty.
// Only returns scripts that are actually executable shell scripts —
// skips `control`, `md5sums`, `conffiles` etc.
// ---------------------------------------------------------------------------
std::vector<std::string> AptAnalyzer::extract_scripts() {
    std::vector<std::string> scripts;

    if (deb_path.empty()) {
        std::cerr << COLOR_RED << "[APT] No .deb to extract — call fetch() first."
                  << COLOR_RESET << std::endl;
        return scripts;
    }

    std::string ctrl_dir = work_dir + "/DEBIAN";
    mkdir(ctrl_dir.c_str(), 0700);

    // dpkg-deb --control extracts the DEBIAN/ control dir
    std::string cmd = "dpkg-deb --control '" + deb_path + "' '" + ctrl_dir + "' 2>&1";
    int rc = system(cmd.c_str());
    if (rc != 0) {
        std::cerr << COLOR_YELLOW << "[APT] Warning: dpkg-deb --control returned "
                  << rc << " — package may have no maintainer scripts."
                  << COLOR_RESET << std::endl;
        // Not fatal — many packages have no maintainer scripts at all
    }

    // The standard maintainer script names
    static const char* script_names[] = {
        "preinst", "postinst", "prerm", "postrm", nullptr
    };

    int found = 0;
    for (int i = 0; script_names[i] != nullptr; i++) {
        std::string path = ctrl_dir + "/" + script_names[i];

        // Check file exists and is non-empty
        struct stat st;
        if (stat(path.c_str(), &st) != 0) continue;
        if (st.st_size == 0) continue;

        // Make sure it's executable
        chmod(path.c_str(), 0755);

        scripts.push_back(path);
        found++;
        std::cout << COLOR_MAGENTA << "[APT]" << COLOR_RESET
                  << " Found maintainer script: " << script_names[i]
                  << " (" << st.st_size << "B)" << std::endl;
    }

    if (found == 0) {
        std::cout << COLOR_YELLOW << "[APT]" << COLOR_RESET
                  << " No maintainer scripts found in this package." << std::endl;
    } else {
        std::cout << COLOR_CYAN << "[APT]" << COLOR_RESET
                  << " " << found << " maintainer script(s) to analyze." << std::endl;
    }

    return scripts;
}

// ---------------------------------------------------------------------------
// cleanup()
// ---------------------------------------------------------------------------
void AptAnalyzer::cleanup() {
    if (!work_dir.empty()) {
        std::string cmd = "rm -rf '" + work_dir + "'";
        system(cmd.c_str());
    }
}
