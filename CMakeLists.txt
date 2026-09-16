cmake_minimum_required(VERSION 3.10)
project(ShadowAnalyzer)

set(CMAKE_CXX_STANDARD 17)

find_library(BPF_LIB bpf)
find_library(ELF_LIB elf)
find_library(Z_LIB z)

# ─── eBPF build pipeline ────────────────────────────────────────────────────

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.o
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86
            -c ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.c
            -o ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.o
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.c
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.skel.h
    COMMAND bpftool gen skeleton ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.o > ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.skel.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.o
)

add_custom_target(bpf_skeleton DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.skel.h)

# ─── Main shadow binary ──────────────────────────────────────────────────────

add_executable(shadow
    core/src/main.cpp
    core/src/sandbox.cpp
    core/src/observer.cpp
    core/src/threat_intel.cpp
    core/src/apt_analyzer.cpp
)

add_dependencies(shadow bpf_skeleton)
target_link_libraries(shadow ${BPF_LIB} ${ELF_LIB} ${Z_LIB})
target_include_directories(shadow PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf)

# ─── Test suite ─────────────────────────────────────────────────────────────
#
# shadow_tests covers everything that can run without root or eBPF:
#   - ThreatIntel classification (is_trusted_cdn, is_malicious)
#   - Rules/IP blocklist file parsing and validation
#   - Observer event classification logic (noise filter, spawn detection)
#   - OverlayFS diff walker (shadow diff)
#
# Does NOT require: kernel 5.8+, BPF_LSM, root, libbpf, npm, or any package.
# Run with:  cd build && ./shadow_tests
#            cd build && ./shadow_tests [threat_intel]
#            cd build && ./shadow_tests [rules]
#            cd build && ./shadow_tests [observer]
#            cd build && ./shadow_tests [diff]

add_executable(shadow_tests
    # Catch2 amalgamated implementation (compiled once)
    tests/catch2/catch_amalgamated.cpp

    # Test suites
    tests/test_threat_intel.cpp
    tests/test_rules_parser.cpp
    tests/test_observer_logic.cpp
    tests/test_diff_walker.cpp

    # Production code under test (no eBPF dependencies)
    core/src/threat_intel.cpp
)

target_include_directories(shadow_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/catch2
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Register with CTest so `make test` / `ctest` works
enable_testing()
add_test(NAME shadow_tests COMMAND shadow_tests)
