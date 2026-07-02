// agent/include/scorer.h
#pragma once
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include "normalized_event.h"

struct ScoringContext {
    std::shared_ptr<NormalizedEvent> event;
    std::vector<float> featureVector;
    float mlScore = 0.0f;
    float graphScore = 0.0f;
    bool patternMatch = false;
    std::vector<std::string> lineage;

    float FinalScore() const {
        float base = mlScore;
        if (patternMatch) base += 0.2f;

        int suspiciousCount = 0;
        if (graphScore > 0.5f) suspiciousCount++;
        if (mlScore > 0.4f) suspiciousCount++;
        if (patternMatch) suspiciousCount++;

        if (suspiciousCount >= 2) {
            base *= 1.3f;
        }

        return std::clamp(base, 0.0f, 1.0f);
    }
};

inline std::string ScoreToLevel(float score) {
    if (score < 0.2f) return "BENIGN";
    if (score < 0.4f) return "LOW";
    if (score < 0.6f) return "MEDIUM";
    if (score < 0.8f) return "HIGH";
    return "CRITICAL";
}
