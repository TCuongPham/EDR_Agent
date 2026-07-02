// agent/include/common.h
#pragma once
#include <stdint.h>

enum class EventType : uint8_t {
    EventProcessCreate = 0,
    EventProcessTerminate,
    EventFileCreate,
    EventFileWrite,
    EventFileDelete,
    EventNetworkConnect,
    EventDNSQuery,
    EventRegistrySet,
    EventRegistryCreate,
    EventProcessAccess
};

// RawEvent structure for in-memory ETW processing
struct RawEvent {
    int64_t timestamp;     // FileTime or nanoseconds
    EventType eventType;
    uint32_t pid;
    uint32_t ppid;
    uint32_t tid;
    uint32_t sessionId;

    // Process fields
    char processName[260];
    char commandLine[2048];
    char imagePath[260];

    // File fields
    char filePath[260];
    uint64_t fileSize;
    float fileEntropy;

    // Network & DNS fields
    uint8_t srcIP[16];     // IPv4-mapped IPv6 or raw IPv6
    uint8_t dstIP[16];
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;      // TCP=6, UDP=17
    char domain[253];      // DNS query domain

    // Registry fields
    char regKeyPath[512];
    char regValue[256];

    // ProcessAccess fields
    uint32_t targetPid;
    uint32_t accessRights;
};
