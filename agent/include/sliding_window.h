// agent/include/sliding_window.h
#pragma once
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>
#include <memory>
#include "normalized_event.h"

class SlidingWindowAggregator {
private:
    struct ProcessActivity {
        std::vector<std::chrono::system_clock::time_point> childSpawns;
        std::vector<std::chrono::system_clock::time_point> regWrites;
        bool runKeyAccess = false;
    };

    std::mutex m_mutex;
    std::unordered_map<uint32_t, ProcessActivity> m_activity;

    void Prune(ProcessActivity& act, std::chrono::system_clock::time_point now);

public:
    SlidingWindowAggregator() = default;

    void Update(std::shared_ptr<NormalizedEvent> evt);
    
    // Feature extraction queries
    uint32_t GetChildSpawnCount(uint32_t pid, std::chrono::seconds windowSec);
    uint32_t GetRegistryWriteCount(uint32_t pid, std::chrono::seconds windowSec);
    bool GetRunKeyAccess(uint32_t pid);
    
    void RemoveProcess(uint32_t pid);
};
