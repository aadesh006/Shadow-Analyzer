#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// AptAnalyzer
//
// Implements Approach 1 apt support: download a .deb package, extract its
// maintainer scripts (preinst, postinst, prerm, postrm), and run each one
// inside Shadow's existing sandbox so the eBPF hooks observe their behaviour.
//
// The real apt install never runs — only the maintainer scripts are executed.
// If they are clean, the caller can proceed with the real install. If not,
// the package is blocked before it touches the system.
//
// Usage:
//   AptAnalyzer analyzer;
//   if (!analyzer.fetch("curl"))    { /* not found */ }
//   auto scripts = analyzer.extract_scripts();
//   // scripts is a list of full paths to extracted maintainer scripts
//   // pass each one to Sandbox::run() via sh
// ---------------------------------------------------------------------------
class AptAnalyzer {
public:
    AptAnalyzer();
    ~AptAnalyzer();

    // Download the .deb for the given package name (or path to local .deb)
    // into a temp working directory under /tmp/shadow_apt_<pid>/.
    // Returns true on success, false if the package was not found or download failed.
    bool fetch(const std::string& package_name_or_path);

    // Extract the DEBIAN/ control directory from the fetched .deb.
    // Returns a list of full paths to executable maintainer scripts found:
    //   preinst, postinst, prerm, postrm (only those that exist and are non-empty).
    std::vector<std::string> extract_scripts();

    // Package metadata — populated after fetch()
    std::string package_name;
    std::string package_version;
    std::string deb_path;       // full path to the downloaded .deb on disk
    std::string work_dir;       // /tmp/shadow_apt_<pid>/

    // Clean up the temp working directory
    void cleanup();

private:
    bool is_local_deb;          // true if user passed a local .deb path directly
};
