// agent/src/pipeline/normalizer.cpp
#include "normalizer.h"
#include <algorithm>
#include <combaseapi.h>
#include <windows.h>
#include <vector>

// Helper to query elevation and system status
static void GetProcessElevationInfo(uint32_t pid, bool& isSystem, std::string& userName) {
    isSystem = false;
    userName = "";
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return;
    
    HANDLE hToken = NULL;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = 0;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            if (elevation.TokenIsElevated) {
                userName = "admin";
            }
        }
        
        GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
        if (size > 0) {
            std::vector<BYTE> buffer(size);
            if (GetTokenInformation(hToken, TokenUser, buffer.data(), size, &size)) {
                PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer.data();
                
                SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
                PSID systemSid = NULL;
                if (AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid)) {
                    if (EqualSid(pTokenUser->User.Sid, systemSid)) {
                        isSystem = true;
                        userName = "system";
                    }
                    FreeSid(systemSid);
                }
            }
        }
        CloseHandle(hToken);
    }
    CloseHandle(hProcess);
}

// Helper to query process name from PID
static std::string QueryProcessNameFromPID(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "";
    
    char buf[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, buf, &size)) {
        std::string path(buf);
        size_t found = path.find_last_of("/\\");
        if (found != std::string::npos) {
            CloseHandle(hProcess);
            return path.substr(found + 1);
        }
        CloseHandle(hProcess);
        return path;
    }
    CloseHandle(hProcess);
    return "";
}

std::string Normalizer::GenerateUUID() {
    GUID guid;
    HRESULT hr = CoCreateGuid(&guid);
    if (SUCCEEDED(hr)) {
        char buffer[39];
        sprintf_s(buffer, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return std::string(buffer);
    }
    return "00000000-0000-0000-0000-000000000000";
}

std::string Normalizer::ToLower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

std::shared_ptr<NormalizedEvent> Normalizer::Normalize(const RawEvent& raw) {
    auto evt = std::make_shared<NormalizedEvent>();
    evt->id = GenerateUUID();
    
    // Standardize to current clock time
    evt->timestamp = std::chrono::system_clock::now();
    evt->pid = raw.pid;
    evt->ppid = raw.ppid;
    evt->sessionId = raw.sessionId;
    
    // Set common identifiers
    evt->processName = ToLower(raw.processName);
    evt->processPath = raw.imagePath;
    evt->commandLine = raw.commandLine;

    if (raw.eventType == EventType::EventProcessCreate) {
        evt->eventType = "ProcessCreate";
        m_processCache[raw.pid] = evt->processName;
        if (m_processCache.count(raw.ppid)) {
            evt->parentName = m_processCache[raw.ppid];
        }
        // Query elevation and system status once at spawn time, cache for later events
        ElevationInfo elev;
        GetProcessElevationInfo(raw.pid, elev.isSystem, elev.userName);
        m_elevationCache[raw.pid] = elev;
        evt->isSystem = elev.isSystem;
        evt->userName = elev.userName;
    } 
    else if (raw.eventType == EventType::EventProcessTerminate) {
        evt->eventType = "ProcessTerminate";
        if (m_processCache.count(raw.pid)) {
            evt->processName = m_processCache[raw.pid];
            m_processCache.erase(raw.pid);
        }
        // Apply elevation info before evicting from cache
        if (m_elevationCache.count(raw.pid)) {
            evt->isSystem = m_elevationCache[raw.pid].isSystem;
            evt->userName = m_elevationCache[raw.pid].userName;
            m_elevationCache.erase(raw.pid);
        }
    }
    else if (raw.eventType == EventType::EventFileCreate) {
        evt->eventType = "FileCreate";
        evt->fields["path"] = std::string(raw.filePath);
        evt->fields["size"] = raw.fileSize;
        evt->fields["entropy"] = raw.fileEntropy;
    }
    else if (raw.eventType == EventType::EventFileWrite) {
        evt->eventType = "FileWrite";
        evt->fields["path"] = std::string(raw.filePath);
        evt->fields["size"] = raw.fileSize;
        evt->fields["entropy"] = raw.fileEntropy;
    }
    else if (raw.eventType == EventType::EventFileDelete) {
        evt->eventType = "FileDelete";
        evt->fields["path"] = std::string(raw.filePath);
    }
    else if (raw.eventType == EventType::EventNetworkConnect) {
        evt->eventType = "NetworkConnect";
        char srcIpStr[46] = {0};
        char dstIpStr[46] = {0};
        
        // Simple representation helper
        if (raw.srcIP[0] == 0 && raw.srcIP[1] == 0 && raw.srcIP[2] == 0 && raw.srcIP[3] == 0 &&
            raw.srcIP[4] == 0 && raw.srcIP[5] == 0 && raw.srcIP[6] == 0 && raw.srcIP[7] == 0 &&
            raw.srcIP[8] == 0 && raw.srcIP[9] == 0 && raw.srcIP[10] == 0xff && raw.srcIP[11] == 0xff) {
            sprintf_s(srcIpStr, "%d.%d.%d.%d", raw.srcIP[12], raw.srcIP[13], raw.srcIP[14], raw.srcIP[15]);
            sprintf_s(dstIpStr, "%d.%d.%d.%d", raw.dstIP[12], raw.dstIP[13], raw.dstIP[14], raw.dstIP[15]);
        } else {
            if (raw.srcIP[0] != 0 || raw.srcIP[1] != 0 || raw.srcIP[2] != 0 || raw.srcIP[3] != 0) {
                sprintf_s(srcIpStr, "%d.%d.%d.%d", raw.srcIP[0], raw.srcIP[1], raw.srcIP[2], raw.srcIP[3]);
                sprintf_s(dstIpStr, "%d.%d.%d.%d", raw.dstIP[0], raw.dstIP[1], raw.dstIP[2], raw.dstIP[3]);
            } else {
                sprintf_s(srcIpStr, "::1");
                sprintf_s(dstIpStr, "::1");
            }
        }
        
        evt->fields["protocol"] = std::string(raw.protocol == 6 ? "tcp" : (raw.protocol == 17 ? "udp" : "other"));
        evt->fields["srcIP"] = std::string(srcIpStr);
        evt->fields["dstIP"] = std::string(dstIpStr);
        evt->fields["srcPort"] = raw.srcPort;
        evt->fields["dstPort"] = raw.dstPort;
    }
    else if (raw.eventType == EventType::EventDNSQuery) {
        evt->eventType = "DNSQuery";
        evt->fields["queryName"] = std::string(raw.domain);
    }
    else if (raw.eventType == EventType::EventRegistrySet) {
        evt->eventType = "RegistrySet";
        evt->fields["keyPath"] = std::string(raw.regKeyPath);
        evt->fields["valueName"] = std::string(raw.regValue);
    }
    else if (raw.eventType == EventType::EventRegistryCreate) {
        evt->eventType = "RegistryCreate";
        evt->fields["keyPath"] = std::string(raw.regKeyPath);
    }
    else if (raw.eventType == EventType::EventProcessAccess) {
        evt->eventType = "ProcessAccess";
        evt->fields["targetPid"] = raw.targetPid;
        evt->fields["accessRights"] = raw.accessRights;
        
        // Resolve target process name dynamically
        std::string targetName = QueryProcessNameFromPID(raw.targetPid);
        if (targetName.empty() && m_processCache.count(raw.targetPid)) {
            targetName = m_processCache[raw.targetPid];
        }
        evt->fields["targetName"] = targetName;
    }
    
    if (evt->parentName.empty() && m_processCache.count(evt->ppid)) {
        evt->parentName = m_processCache[evt->ppid];
    }

    // Apply cached elevation info to all non-Create/non-Terminate events
    if (evt->eventType != "ProcessCreate" && evt->eventType != "ProcessTerminate") {
        if (m_elevationCache.count(raw.pid)) {
            evt->isSystem = m_elevationCache[raw.pid].isSystem;
            evt->userName = m_elevationCache[raw.pid].userName;
        }
    }
    
    return evt;
}
