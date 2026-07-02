// agent/include/telemetry/dns.h
#pragma once
#include "base.h"

struct DNSQueryEvent : public BaseEvent {
    // Query details
    std::string queryName;        // "evil.badactor.com"
    std::string queryType;        // "A", "AAAA", "MX", "TXT"
    std::vector<std::string> resolvedIPs; // ["1.2.3.4"]
    
    // Anomaly flags
    bool isKnownBadDomain = false;// IOC list match
    bool isDga = false;           // Domain Generation Algorithm detected
    float dgaScore = 0.0f;        // [0,1]
    bool isLongSubdomain = false; // DNS tunneling indicator
    int subdomainLength = 0;
    float entropyDomain = 0.0f;   // Shannon entropy of domain name
    
    // Statistical features
    float queryFreqPerMin = 0.0f;
    float nxDomainRate = 0.0f;
};
