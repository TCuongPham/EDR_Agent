// agent/include/response.h
#pragma once
#include <string>
#include <vector>
#include <memory>
#include "scorer.h"

struct PolicyRule {
    float minScore;
    float maxScore;
    std::vector<std::string> actions;
    std::string alertLevel;
};

class ResponseHandler {
private:
    std::vector<PolicyRule> m_rules;

    void SendAlert(const ScoringContext& ctx, float score);
    bool KillProcess(uint32_t pid);
    void BlockNetworkForProcess(uint32_t pid);

public:
    ResponseHandler(const std::string& policyPath);
    void Handle(const ScoringContext& ctx);
};
