cmake_minimum_required(VERSION 3.15)
project(EDR_AI_Agent C CXX)

# Global compiler/build configuration
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build the user-space EDR agent target
add_subdirectory(agent)
