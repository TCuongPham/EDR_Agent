// agent/include/telemetry/process_access.h
#pragma once
#include "base.h"

struct ProcessAccessEvent : public BaseEvent {
    // Access details
    uint32_t targetPid;
    std::string targetProcessName; // "lsass.exe"
    std::string targetProcessPath;
    uint32_t accessRights;         // Hex: 0x1410
    std::string accessRightsStr;   // "PROCESS_VM_READ|PROCESS_QUERY_INFO"
    
    // Classification
    bool isLsassAccess = false;    // Target is lsass.exe
    bool isCredentialDump = false; // Rights sufficient for dumping credentials
    std::string callStack;         // Top call stack frames if ETW
};
