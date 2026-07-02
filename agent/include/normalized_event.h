// agent/include/normalized_event.h
#pragma once
#include <string>
#include <chrono>
#include <unordered_map>
#include <any>

struct NormalizedEvent {
    std::string id;         // UUID v4
    std::chrono::system_clock::time_point timestamp;
    std::string eventType;  // "ProcessCreate", "FileWrite", etc.
    
    // Process context
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::string processName;
    std::string processPath;
    std::string commandLine;
    std::string userName;
    uint32_t sessionId = 0;
    
    // Event-specific fields
    std::unordered_map<std::string, std::any> fields;
    
    // Enriched fields
    std::string parentName;
    bool isSystem = false;
    int depth = 0;
};
