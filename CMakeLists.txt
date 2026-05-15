cmake_minimum_required(VERSION 3.10)
project(ShadowAnalyzer)

set(CMAKE_CXX_STANDARD 17)

find_library(BPF_LIB bpf)
find_library(ELF_LIB elf)
find_library(Z_LIB z)

#Compile C to eBPF bytecode
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.o
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86 
            -c ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.c 
            -o ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.o
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.c
)

#Generate C++ Skeleton
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.skel.h
    COMMAND bpftool gen skeleton ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.o > ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.skel.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.bpf.o
)

#Custom target barrier
add_custom_target(bpf_skeleton DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf/shadow.skel.h)

#Main executable
add_executable(shadow 
    core/src/main.cpp
    core/src/sandbox.cpp
    core/src/observer.cpp
    core/src/parser.cpp
    core/src/threat_intel.cpp
)

add_dependencies(shadow bpf_skeleton)
target_link_libraries(shadow ${BPF_LIB} ${ELF_LIB} ${Z_LIB})
target_include_directories(shadow PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core/src/bpf)