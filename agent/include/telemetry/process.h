// agent/include/telemetry/process.h
#pragma once
#include "base.h"

// ProcessCreateEvent — Fired when a new process is created
struct ProcessCreateEvent : public BaseEvent {
    // Process Identity
    std::string imageHash;       // SHA256 of executable
    std::string imageHashMD5;    // MD5
    std::string commandLine;     // Full command line with arguments
    std::string currentDir;      // Working directory
    
    // Parent Process
    uint32_t parentPid;
    std::string parentName;      // "winword.exe"
    std::string parentPath;      // Full path of parent
    std::string parentCmdLine;   // CommandLine of parent
    
    // Signatures & Trust
    bool isSigned = false;       // PE has digital signature
    std::string signerName;      // "Microsoft Corporation"
    bool isVerified = false;     // Signature is valid
    
    // Computed flags
    bool isHollowed = false;     // Suspected process hollowing
    bool isInjected = false;     // Suspected injection
    bool isLOLBin = false;       // Is Living-off-the-Land binary
    bool hasEncodedArgs = false; // Command line has base64 encoded content
    int depthInTree = 0;         // Depth in process tree
    
    // Token & Privilege
    bool tokenElevated = false;  // Token has elevated privilege
    std::string tokenType;       // "Primary" / "Impersonation"
};

// ProcessTerminateEvent — Fired when a process exits
struct ProcessTerminateEvent : public BaseEvent {
    int32_t exitCode = 0;
    int64_t lifetimeMs = 0;      // Lifetime in ms
    uint64_t peakMemoryKB = 0;
};
