// agent/src/features/lineage_graph.cpp
#include "lineage_graph.h"
#include <algorithm>

void BehaviorGraph::EvictOldest() {
    uint32_t oldestPid = 0;
    auto oldestTime = std::chrono::system_clock::time_point::max();
    
    // Pass 1: Exited processes
    for (const auto& [pid, node] : m_nodes) {
        if (node->endTime != std::chrono::system_clock::time_point() && node->startTime < oldestTime) {
            oldestTime = node->startTime;
            oldestPid = pid;
        }
    }
    
    // Pass 2: Overall if no exited process found
    if (oldestPid == 0) {
        for (const auto& [pid, node] : m_nodes) {
            if (node->startTime < oldestTime) {
                oldestTime = node->startTime;
                oldestPid = pid;
            }
        }
    }
    
    if (oldestPid != 0) {
        auto node = m_nodes[oldestPid];
        uint32_t ppid = node->ppid;
        if (m_children.count(ppid)) {
            auto& childList = m_children[ppid];
            childList.erase(std::remove(childList.begin(), childList.end(), oldestPid), childList.end());
        }
        m_nodes.erase(oldestPid);
        m_children.erase(oldestPid);
    }
}

void BehaviorGraph::AddProcess(std::shared_ptr<ProcessNode> node) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_nodes.size() >= m_maxNodes) {
        EvictOldest();
    }
    
    // Handle PID recycling
    if (m_nodes.count(node->pid)) {
        auto oldNode = m_nodes[node->pid];
        uint32_t oldPpid = oldNode->ppid;
        if (m_children.count(oldPpid)) {
            auto& childList = m_children[oldPpid];
            childList.erase(std::remove(childList.begin(), childList.end(), node->pid), childList.end());
        }
        m_nodes.erase(node->pid);
        m_children.erase(node->pid);
    }
    
    // Calculate depth
    auto it = m_nodes.find(node->ppid);
    if (it != m_nodes.end()) {
        node->depth = it->second->depth + 1;
    } else {
        node->depth = 1; // Root
    }
    
    m_nodes[node->pid] = node;
    m_children[node->ppid].push_back(node->pid);
}

void BehaviorGraph::RemoveProcess(uint32_t pid) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_nodes.count(pid)) {
        auto node = m_nodes[pid];
        node->endTime = std::chrono::system_clock::now();
        
        uint32_t ppid = node->ppid;
        if (m_children.count(ppid)) {
            auto& childList = m_children[ppid];
            childList.erase(std::remove(childList.begin(), childList.end(), pid), childList.end());
        }
        
        m_nodes.erase(pid);
        m_children.erase(pid);
    }
}

std::vector<std::shared_ptr<ProcessNode>> BehaviorGraph::GetLineage(uint32_t pid) {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<std::shared_ptr<ProcessNode>> chain;
    uint32_t current = pid;
    
    for (int i = 0; i < 50; ++i) { // Limit to 50 levels to prevent loops
        auto it = m_nodes.find(current);
        if (it != m_nodes.end()) {
            auto node = it->second;
            chain.insert(chain.begin(), node); // Prepend
            if (node->ppid == 0 || node->ppid == current) {
                break;
            }
            current = node->ppid;
        } else {
            break;
        }
    }
    return chain;
}

bool BehaviorGraph::MatchPattern(uint32_t pid, const std::vector<std::string>& pattern) {
    auto lineage = GetLineage(pid);
    if (lineage.size() < pattern.size()) return false;

    for (size_t i = 0; i <= lineage.size() - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            // Case-insensitive substring match
            std::string nodeName = lineage[i + j]->name;
            std::string patName = pattern[j];
            std::transform(nodeName.begin(), nodeName.end(), nodeName.begin(), ::tolower);
            std::transform(patName.begin(), patName.end(), patName.begin(), ::tolower);
            if (nodeName.find(patName) == std::string::npos) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

int BehaviorGraph::GetDepth(uint32_t pid) {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it != m_nodes.end()) {
        return it->second->depth;
    }
    return 1;
}

int BehaviorGraph::GetMaxFanOut(uint32_t pid) {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<uint32_t> lineagePids;
    uint32_t current = pid;
    for (int i = 0; i < 50; ++i) {
        auto it = m_nodes.find(current);
        if (it != m_nodes.end()) {
            lineagePids.push_back(current);
            if (it->second->ppid == 0 || it->second->ppid == current) {
                break;
            }
            current = it->second->ppid;
        } else {
            break;
        }
    }
    
    int maxFan = 0;
    for (uint32_t lPid : lineagePids) {
        auto it = m_children.find(lPid);
        if (it != m_children.end()) {
            int fan = static_cast<int>(it->second.size());
            if (fan > maxFan) {
                maxFan = fan;
            }
        }
    }
    return maxFan;
}

std::shared_ptr<ProcessNode> BehaviorGraph::GetNode(uint32_t pid) {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it != m_nodes.end()) {
        return it->second;
    }
    return nullptr;
}
