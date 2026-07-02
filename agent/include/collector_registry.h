// agent/include/collector_registry.h
#pragma once
#include <unordered_map>
#include <memory>
#include <string>
#include <fstream>
#include <iostream>
#include "collector.h"
#include "nlohmann/json.hpp"

class CollectorRegistry {
private:
    std::unordered_map<std::string, std::shared_ptr<ICollector>> m_collectors;

public:
    void RegisterCollector(std::shared_ptr<ICollector> collector) {
        if (collector) {
            m_collectors[collector->GetName()] = collector;
        }
    }

    bool LoadConfigAndStart(const std::string& configPath) {
        std::ifstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[CollectorRegistry] Failed to open config: " << configPath << std::endl;
            return false;
        }

        nlohmann::json j;
        try {
            file >> j;
        } catch (const std::exception& e) {
            std::cerr << "[CollectorRegistry] JSON parsing error: " << e.what() << std::endl;
            return false;
        }

        std::cout << "[CollectorRegistry] Dynamic registration starting (Agent ID: " 
                  << j.value("agent_id", "unknown") << ")" << std::endl;

        if (!j.contains("collectors")) {
            std::cerr << "[CollectorRegistry] No 'collectors' key found in config." << std::endl;
            return false;
        }

        for (auto& [name, col] : m_collectors) {
            bool enabled = false;
            if (j["collectors"].contains(name)) {
                enabled = j["collectors"][name]["enabled"].get<bool>();
            }

            if (enabled) {
                if (col->Start()) {
                    std::cout << "[CollectorRegistry] Started collector: " << name << std::endl;
                } else {
                    std::cerr << "[CollectorRegistry] Failed to start collector: " << name << std::endl;
                }
            } else {
                std::cout << "[CollectorRegistry] Disabled collector: " << name << std::endl;
            }
        }
        return true;
    }

    void StopAll() {
        for (auto& [name, col] : m_collectors) {
            std::cout << "[CollectorRegistry] Stopping collector: " << name << std::endl;
            col->Stop();
        }
    }
};
