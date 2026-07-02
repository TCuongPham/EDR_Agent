// agent/include/normalizer.h
#pragma once
#include <memory>
#include <unordered_map>
#include "common.h"
#include "normalized_event.h"

struct ElevationInfo {
    bool isSystem = false;
    std::string userName;
};

class Normalizer {
private:
    std::unordered_map<uint32_t, std::string> m_processCache;
    std::unordered_map<uint32_t, ElevationInfo> m_elevationCache;

    std::string GenerateUUID();
    std::string ToLower(std::string str);

public:
    std::shared_ptr<NormalizedEvent> Normalize(const RawEvent& raw);
};
