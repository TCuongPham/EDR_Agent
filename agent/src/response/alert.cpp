// agent/src/response/alert.cpp
#include "response.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <iostream>

ResponseHandler::ResponseHandler(const std::string& policyPath) {
    std::ifstream file(policyPath);
    if (!file.is_open()) {
        std::cerr << "[ResponseHandler] Warning: Failed to open response policy config at " << policyPath << std::endl;
        return;
    }
    
    try {
        nlohmann::json j;
        file >> j;
        
        for (const auto& item : j["rules"]) {
            PolicyRule rule;
            rule.minScore = item["min_score"].get<float>();
            rule.maxScore = item["max_score"].get<float>();
            rule.actions = item["actions"].get<std::vector<std::string>>();
            rule.alertLevel = item["alert_level"].get<std::string>();
            m_rules.push_back(rule);
        }
        std::cout << "[ResponseHandler] Loaded " << m_rules.size() << " threat response rules from " << policyPath << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ResponseHandler] Exception parsing policy config: " << e.what() << std::endl;
    }
}

void ResponseHandler::Handle(const ScoringContext& ctx) {
    float score = ctx.FinalScore();
    
    for (const auto& rule : m_rules) {
        if (score >= rule.minScore && score < rule.maxScore) {
            for (const auto& action : rule.actions) {
                if (action == "alert") {
                    SendAlert(ctx, score);
                } else if (action == "kill") {
                    KillProcess(ctx.event->pid);
                } else if (action == "block") {
                    BlockNetworkForProcess(ctx.event->pid);
                }
            }
            break;
        }
    }
}

void ResponseHandler::SendAlert(const ScoringContext& ctx, float score) {
    std::cout << "\n>>> [ALERT] THREAT DETECTED!" << std::endl;
    std::cout << "  - Level:       " << ScoreToLevel(score) << " (Score: " << score << ")" << std::endl;
    std::cout << "  - Process:     " << ctx.event->processName << " (PID: " << ctx.event->pid << ")" << std::endl;
    std::cout << "  - Commandline: " << ctx.event->commandLine << std::endl;
    std::cout << "  - Event Type:  " << ctx.event->eventType << std::endl;
    if (!ctx.lineage.empty()) {
        std::cout << "  - Ancestry:    ";
        for (size_t i = 0; i < ctx.lineage.size(); ++i) {
            std::cout << ctx.lineage[i] << (i == ctx.lineage.size() - 1 ? "" : " -> ");
        }
        std::cout << std::endl;
    }
    std::cout << "<<<\n" << std::endl;
}
