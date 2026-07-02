// agent/include/telemetry/file.h
#pragma once
#include "base.h"

enum class FileEventType {
    FileEventCreate,
    FileEventWrite,
    FileEventDelete,
    FileEventRename,
    FileEventADS     // Alternate Data Stream
};

struct FileEvent : public BaseEvent {
    FileEventType fileEventType;

    // File Identity
    std::string filePath;         // "C:\Users\john\Documents\budget.xlsx"
    std::string fileExtension;    // "xlsx", "exe", "ps1"
    uint64_t fileSize = 0;        // Bytes
    std::string fileHash;         // SHA256 (if computed)
    
    // Entropy Analysis (Ransomware detection)
    float entropy = 0.0f;         // Shannon entropy [0.0, 8.0]
    std::string entropyCategory;  // "low"/"medium"/"high"
    bool isEncrypted = false;     // Entropy > 7.5
    
    // Path Analysis
    bool isSystemPath = false;    // In Windows/ or System32/
    bool isTempPath = false;      // In %TEMP%, %APPDATA%
    bool isSensitivePath = false; // SAM, NTDS.dit, lsass dump paths
    bool isAds = false;           // Alternate Data Stream
    
    // Rename specific
    std::string oldFilePath;      // For FileRename
    std::string newExtension;     // For rename changing extension
    
    // Aggregated stats
    float fileWriteRatePerMin = 0.0f;
    int uniqueExtModified = 0;
};
