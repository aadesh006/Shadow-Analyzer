#include "../include/observer.h"
#include "shadow.skel.h"
#include <bpf/libbpf.h>
#include <iostream>

const std::string COLOR_RESET   = "\033[0m";
const std::string COLOR_MAGENTA = "\033[1;35m";
const std::string COLOR_RED     = "\033[1;31m";

Observer::Observer() : skel(nullptr), rb(nullptr), running(false) {}

Observer::~Observer() {
    stop();
}