// agent/src/features/sliding_window.cpp
#include "sliding_window.h"
#include <algorithm>

void SlidingWindowAggregator::Prune(ProcessActivity& act, std::chrono::system_clock::time_point now) {
    auto cutoff = now - std::chrono::seconds(300); // Max window is 300s
    
    // Prune child spawns
    auto it1 = std::lower_bound(act.childSpawns.begin(), act.childSpawns.end(), cutoff);
    if (it1 != act.childSpawns.begin()) {
        act.childSpawns.erase(act.childSpawns.begin(), it1);
    }
    
    // Prune registry writes
    auto it2 = std::lower_bound(act.regWrites.begin(), act.regWrites.end(), cutoff);
    if (it2 != act.regWrites.begin()) {
        act.regWrites.erase(act.regWrites.begin(), it2);
    }
}

void SlidingWindowAggregator::Update(std::shared_ptr<NormalizedEvent> evt) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto now = evt->timestamp;
    
    if (evt->eventType == "ProcessCreate") {
        // Child spawn belongs to the parent!
        auto& parentAct = m_activity[evt->ppid];
        parentAct.childSpawns.push_back(now);
        Prune(parentAct, now);
    }
    else if (evt->eventType == "RegistrySet" || evt->eventType == "RegistryCreate") {
        auto& act = m_activity[evt->pid];
        act.regWrites.push_back(now);
        
        std::string keyPath = "";
        if (evt->fields.count("keyPath")) {
            try {
                keyPath = std::any_cast<std::string>(evt->fields.at("keyPath"));
            } catch (...) {}
        }
        std::transform(keyPath.begin(), keyPath.end(), keyPath.begin(), ::tolower);
        bool isPersistence = (keyPath.find("\\run") != std::string::npos ||
                              keyPath.find("\\runonce") != std::string::npos ||
                              keyPath.find("\\services") != std::string::npos);
        if (isPersistence) {
            act.runKeyAccess = true;
        }
        Prune(act, now);
    }
}

uint32_t SlidingWindowAggregator::GetChildSpawnCount(uint32_t pid, std::chrono::seconds windowSec) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_activity.find(pid);
    if (it == m_activity.end()) return 0;
    
    auto now = std::chrono::system_clock::now();
    auto cutoff = now - windowSec;
    
    uint32_t count = 0;
    for (const auto& ts : it->second.childSpawns) {
        if (ts >= cutoff) {
            count++;
        }
    }
    return count;
}

uint32_t SlidingWindowAggregator::GetRegistryWriteCount(uint32_t pid, std::chrono::seconds windowSec) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_activity.find(pid);
    if (it == m_activity.end()) return 0;
    
    auto now = std::chrono::system_clock::now();
    auto cutoff = now - windowSec;
    
    uint32_t count = 0;
    for (const auto& ts : it->second.regWrites) {
        if (ts >= cutoff) {
            count++;
        }
    }
    return count;
}

bool SlidingWindowAggregator::GetRunKeyAccess(uint32_t pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_activity.find(pid);
    if (it == m_activity.end()) return false;
    return it->second.runKeyAccess;
}

void SlidingWindowAggregator::RemoveProcess(uint32_t pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_activity.erase(pid);
}
