cmake_minimum_required(VERSION 3.15)
project(edr_agent C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Executable target sources including sqlite3.c
set(SOURCES
    src/main.cpp
    src/collector/collector.cpp
    src/pipeline/normalizer.cpp
    src/features/lineage_graph.cpp
    src/features/sliding_window.cpp
    src/features/entropy.cpp
    src/inference/onnx_inferencer.cpp
    src/inference/rule_engine.cpp
    src/inference/scorer.cpp
    src/response/alert.cpp
    src/response/kill_process.cpp
    src/response/block_network.cpp
    third_party/sqlite/sqlite3.c
)

# Executable target
add_executable(edr_agent ${SOURCES})

# Include directories
target_include_directories(edr_agent PRIVATE 
    include 
    third_party 
    third_party/sqlite
    third_party/onnxruntime/include
)

# Link Windows libraries needed for ETW, TDH, and GUID resolution + ONNX Runtime
target_link_libraries(edr_agent PRIVATE
    tdh
    ole32
    advapi32
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/onnxruntime/lib/onnxruntime.lib"
)

# Copy ONNX Runtime DLLs to the executable directory after building
add_custom_command(TARGET edr_agent POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/onnxruntime/lib/onnxruntime.dll"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/onnxruntime/lib/onnxruntime_providers_shared.dll"
    $<TARGET_FILE_DIR:edr_agent>
)
