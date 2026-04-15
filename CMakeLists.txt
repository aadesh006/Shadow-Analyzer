cmake_minimum_required(VERSION 3.10)
project(ShadowAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#core executable
add_executable(shadow 
    core/src/main.cpp
    core/src/sandbox.cpp
)
