// agent/include/telemetry/base.h
#pragma once
#include <string>
#include <vector>
#include <chrono>

const std::string SchemaVersion = "1.0";

enum class EventCategory {
    Process,
    File,
    Network,
    Registry,
    Memory,
    DNS
};

enum class EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

struct BaseEvent {
    // Identity
    std::string eventId;        // UUID v4
    std::string schemaVersion;  // "1.0"
    EventCategory eventCategory;
    std::string eventType;      // "ProcessCreate", ...
    std::string etwProviderGUID; // GUID của ETW Provider tương ứng
    int etwEventId;              // Event ID thô của ETW Provider

    // Timing
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point collectedAt;
    int64_t bootTimestamp;      // Nanoseconds từ boot (QPC)

    // Host context
    std::string hostname;
    std::string agentId;
    std::string osVersion;
    std::string agentVersion;

    // Process context (present in all events)
    uint32_t pid;
    uint32_t ppid;
    std::string processName;
    std::string processPath;
    std::string username;
    std::string userSid;
    uint32_t sessionId;
    std::string integrity;      // "Low", "Medium", "High", "System"

    // AI metadata (filled after inference)
    float threatScore = -1.0f;  // -1.0f if not yet inferred
    std::string threatLevel;    // "BENIGN"/"LOW"/"MEDIUM"/"HIGH"/"CRITICAL"
    EventSeverity severity = EventSeverity::Info;
    std::vector<std::string> tags; // ["lolbin", "encoded_ps", ...]
};
