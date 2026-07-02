// agent/include/lineage_graph.h
#pragma once
#include <unordered_map>
#include <vector>
#include <string>
#include <shared_mutex>
#include <chrono>
#include <memory>

struct ProcessNode {
    uint32_t pid;
    uint32_t ppid;
    std::string name;
    std::string path;
    std::string commandLine;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    int depth = 0;
    
    // Dynamic attributes for generic behavior correlation (Stage-3 / Tier-3)
    std::unordered_map<std::string, std::string> attributes;
    std::unordered_map<std::string, float> metrics;

    void SetAttribute(const std::string& key, const std::string& val) {
        attributes[key] = val;
    }
    std::string GetAttribute(const std::string& key) const {
        auto it = attributes.find(key);
        return it != attributes.end() ? it->second : "";
    }
    
    bool hasLSASSAccess() const { return GetAttribute("lsass_access") == "1"; }
};

class BehaviorGraph {
private:
    std::shared_mutex m_mutex;
    std::unordered_map<uint32_t, std::shared_ptr<ProcessNode>> m_nodes;
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_children; // PPID -> list of PIDs (Adjacency List)
    size_t m_maxNodes;

    void EvictOldest();

public:
    BehaviorGraph(size_t maxNodes = 10000) : m_maxNodes(maxNodes) {}

    void AddProcess(std::shared_ptr<ProcessNode> node);
    void RemoveProcess(uint32_t pid);
    std::vector<std::shared_ptr<ProcessNode>> GetLineage(uint32_t pid);
    bool MatchPattern(uint32_t pid, const std::vector<std::string>& pattern);
    
    // Feature extraction helpers
    int GetDepth(uint32_t pid);
    int GetMaxFanOut(uint32_t pid);
    std::shared_ptr<ProcessNode> GetNode(uint32_t pid);
};
