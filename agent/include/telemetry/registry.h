// agent/include/telemetry/registry.h
#pragma once
#include "base.h"

struct RegistrySetEvent : public BaseEvent {
    // Registry details
    std::string keyPath;          // Full registry key path
    std::string valueName;        // Registry value name
    std::string valueType;        // "REG_SZ", "REG_BINARY", "REG_DWORD"
    std::string valueData;        // Value (truncated at 512 chars)
    int valueDataLen = 0;         // Byte length
    
    // Persistence classification
    bool isPersistenceKey = false;// Run/RunOnce/Services/...
    std::string persistenceType;  // "autorun", "service", "ifeo", "wmi"
    bool isLaunchable = false;    // Value points to executable
    
    // IFEO (Image File Execution Options) hijacking
    bool isIfeo = false;          // IFEO key modification
    std::string ifeoTarget;        // Target process hijacked
};
