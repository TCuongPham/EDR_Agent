// agent/include/telemetry/alert.h
#pragma once
#include <string>
#include <vector>
#include <chrono>

// AlertEvent is the final output when the agent detects a threat
struct AlertEvent {
    // Alert identity
    std::string alertId;
    std::chrono::system_clock::time_point createdAt;
    
    // Threat assessment
    float threatScore = 0.0f;     // [0.0, 1.0]
    std::string threatLevel;     // "HIGH"/"CRITICAL"
    float confidence = 0.0f;      // Model confidence
    
    // MITRE ATT&CK mapping
    std::vector<std::string> mitreTactics;     // ["Execution", "Persistence"]
    std::vector<std::string> mitreTechniques;   // ["T1059.001", "T1547.001"]
    
    // Evidence
    std::string triggerEventId;   // EventID that triggered the alert
    std::vector<std::string> processChain;      // ["winword.exe->powershell.exe->rundll32.exe"]
    std::vector<std::string> indicators;        // ["encoded_ps", "lolbin", "c2_beacon"]
    
    // Response taken
    std::vector<std::string> actionsTaken;      // ["kill_process", "alert"]
    
    // Raw event snapshot (serialized as JSON string)
    std::string triggerEventJson;
};
