// agent/include/telemetry/network.h
#pragma once
#include "base.h"

struct NetworkConnectEvent : public BaseEvent {
    // Connection details
    std::string protocol;         // "tcp", "udp", "icmp"
    std::string direction;        // "outbound", "inbound"
    std::string srcIP;            // Source IP
    uint16_t srcPort = 0;
    std::string dstIP;            // Destination IP
    uint16_t dstPort = 0;
    std::string dstHostname;      // Resolved hostname if any

    // Geo & Threat Intel
    std::string dstCountry;       // "CN", "RU", "US"
    std::string dstASN;           // Autonomous System Number
    bool isKnownBad = false;      // Matches IOC list
    bool isTor = false;           // TOR exit node
    bool isVpn = false;           // VPN range

    // Port analysis
    bool isSuspiciousPort = false;// Non-standard ports: 4444, 1337, etc.
    std::string portCategory;     // "well-known", "registered", "dynamic"
    
    // Behavioral
    float connectionsPerMin = 0.0f;
    int uniqueDestIPs = 0;
    float beaconScore = 0.0f;
};
