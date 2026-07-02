# Telemetry Specification — EDR AI Agent
## Định nghĩa Cấu trúc Dữ liệu Sự kiện Hệ thống

> **Phiên bản**: v1.0 | **Ngày**: 2026-06-07  
> **Mục đích**: Chuẩn hóa JSON schema và C++ struct cho toàn bộ event telemetry

---

## 1. Thiết kế Triết lý

```
Nguyên tắc:
1. MINIMAL ALLOCATION — Struct tối giản, tránh nested object không cần thiết
2. FLAT STRUCTURE — JSON flat thay vì deep nested (tối ưu parse speed)
3. TYPED FIELDS — Dùng kiểu dữ liệu cụ thể thay vì `interface{}`
4. VERSIONED — Mỗi event có schema_version để backward compat
5. SELF-DESCRIBING — Mỗi event đủ ngữ cảnh để xử lý độc lập
6. COLLECTOR-AGNOSTIC — Feature engine hoạt động bình thường kể cả khi một collector bị tắt;
   giá trị mặc định (0.0 / -1.0) được gán tự động cho các đặc trưng không có dữ liệu
7. DYNAMIC SHAPE — Agent không gán cứng số chiều Feature Vector; shape được
   truy vấn runtime từ metadata của mô hình ONNX được tải

Transport: JSON over Unix Domain Socket hoặc Named Pipe (Windows)
Storage:   SQLite (WAL mode) + In-memory Ring Buffer
```

---

## 2. Base Event Schema

Tất cả event chia sẻ một **BaseEvent** header chung:

### 2.1 C++ Struct Definition

```cpp
// agent/include/telemetry/base.h
#pragma once
#include <string>
#include <vector>
#include <chrono>

const std::string SchemaVersion = "1.0";

enum class EventCategory {
    Process,
    Registry,
    Memory
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
    int etwEventId;              // Event ID thô của ETW Provider (ví dụ: Event 1=ProcessStart của Kernel-Process)

    // Timing
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point collectedAt;
    int64_t bootTimestamp;      // Nanoseconds từ boot (QPC)

    // Host context
    std::string hostname;
    std::string agentId;
    std::string osVersion;
    std::string agentVersion;

    // Process context (có mặt ở mọi event)
    uint32_t pid;
    uint32_t ppid;
    std::string processName;
    std::string processPath;
    std::string username;
    std::string userSid;
    uint32_t sessionId;
    std::string integrity;      // "Low", "Medium", "High", "System"

    // AI metadata (điền sau khi inference)
    float threatScore = -1.0f;  // -1.0f nếu chưa infer
    std::string threatLevel;    // "BENIGN"/"LOW"/"MEDIUM"/"HIGH"/"CRITICAL"
    EventSeverity severity;
    std::vector<std::string> tags; // ["lolbin", "encoded_ps", ...]
};
```

### 2.2 JSON Example — BaseEvent

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "schema_version": "1.0",
  "event_category": "process",
  "event_type": "ProcessCreate",
  "etw_provider_guid": "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716",
  "etw_event_id": 1,
  "timestamp": "2026-06-07T09:00:00.123456789Z",
  "collected_at": "2026-06-07T09:00:00.125000000Z",
  "boot_timestamp": 123456789000,
  "hostname": "WORKSTATION-01",
  "agent_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
  "os_version": "Windows 10 22H2 (19045)",
  "agent_version": "0.1.0",
  "pid": 4892,
  "ppid": 3210,
  "process_name": "powershell.exe",
  "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "username": "CORP\\john.doe",
  "user_sid": "S-1-5-21-3623811015-3361044348-30300820-1013",
  "session_id": 1,
  "integrity": "Medium",
  "threat_score": null,
  "threat_level": null,
  "severity": "info",
  "tags": []
}
```

---

## 3. Event-Specific Schemas

### 3.1 ProcessCreate Event (ETW Kernel-Process Event 1)

```cpp
// agent/include/telemetry/process.h
#pragma once
#include "base.h"

// ProcessCreateEvent — Fired khi một tiến trình mới được tạo
struct ProcessCreateEvent : public BaseEvent {
    // Process Identity
    std::string imageHash;       // SHA256 của executable
    std::string imageHashMD5;    // MD5 (cho IOC lookup)
    std::string commandLine;     // Full command line với arguments
    std::string currentDir;      // Working directory
    
    // Parent Process
    uint32_t parentPid;
    std::string parentName;      // "winword.exe"
    std::string parentPath;      // Full path của parent
    std::string parentCmdLine;   // CommandLine của parent
    
    // Signatures & Trust
    bool isSigned;               // PE có digital signature
    std::string signerName;      // "Microsoft Corporation"
    bool isVerified;             // Signature còn hợp lệ
    
    // Computed flags (Rule Engine gán)
    bool isHollowed;             // Suspected process hollowing
    bool isInjected;             // Suspected injection
    bool isLOLBin;               // Là Living-off-the-Land binary
    bool hasEncodedArgs;         // Command line có base64 encoded content
    int depthInTree;             // Độ sâu trong process tree
    
    // Token & Privilege
    bool tokenElevated;          // Token có elevated privilege
    std::string tokenType;       // "Primary" / "Impersonation"
};
```

```json
{
  "event_id": "...",
  "event_category": "process",
  "event_type": "ProcessCreate",
  "etw_provider_guid": "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716",
  "etw_event_id": 1,
  "pid": 4892,
  "ppid": 3210,
  "process_name": "powershell.exe",
  "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "image_hash": "a3f5e2d1c4b6a8f0e2d4c6b8a0f2e4d6c8b0a2f4e6d8c0b2a4f6e8d0c2b4a6f8",
  "image_hash_md5": "de4ec93b89d43e9a0e4b5f7c2a1b3d5e",
  "command_line": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
  "current_dir": "C:\\Users\\john.doe\\Downloads",
  "parent_pid": 3210,
  "parent_name": "winword.exe",
  "parent_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "parent_cmdline": "WINWORD.EXE /n \"C:\\Users\\john.doe\\Downloads\\invoice.docm\"",
  "is_signed": true,
  "signer_name": "Microsoft Corporation",
  "is_verified": true,
  "is_hollowed": false,
  "is_injected": false,
  "is_lolbin": true,
  "has_encoded_args": true,
  "depth_in_tree": 3,
  "token_elevated": false,
  "token_type": "Primary",
  "severity": "high",
  "tags": ["encoded_ps", "office_macro_spawn", "lolbin"]
}
```

---

### 3.2 ProcessTerminate Event (ETW Kernel-Process Event 2)

```cpp
struct ProcessTerminateEvent : public BaseEvent {
    int32_t exitCode;
    int64_t lifetimeMs;         // Thời gian sống (ms)
    uint64_t peakMemoryKB;
};
```

---

### 3.3 FileCreate / FileWrite / FileDelete Events (ETW Kernel-File Event 64, 69)
---

### 3.3 File, Network, DNS Events (Đã loại bỏ khỏi Scope)
*Các sự kiện liên quan đến giám sát File, Mạng và DNS đã bị loại bỏ khỏi cấu hình và phân tích của EDR Agent nhằm tối ưu tài nguyên.*

---

### 3.6 RegistrySet Event (ETW Kernel-Registry Event 5)

```cpp
// agent/include/telemetry/registry.h
#pragma once
#include "base.h"

struct RegistrySetEvent : public BaseEvent {
    // Registry details
    std::string keyPath;          // Full registry key path
    std::string valueName;        // Registry value name
    std::string valueType;        // "REG_SZ", "REG_BINARY", "REG_DWORD"
    std::string valueData;        // Giá trị (truncated tại 512 chars)
    int valueDataLen;             // Byte length thực
    
    // Persistence classification
    bool isPersistenceKey;        // Run/RunOnce/Services/...
    std::string persistenceType;  // "autorun", "service", "ifeo", "wmi"
    bool isLaunchable;            // Giá trị point đến executable
    
    // IFEO (Image File Execution Options) hijacking
    bool isIfeo;                  // IFEO key modification
    std::string ifeoTarget;        // Target process bị hijack
};
```

```json
{
  "event_category": "registry",
  "event_type": "RegistrySet",
  "etw_provider_guid": "70eb4f03-c1de-4f73-a051-33d13d5413bd",
  "etw_event_id": 5,
  "pid": 5312,
  "process_name": "malware.exe",
  "key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "value_name": "WindowsUpdate",
  "value_type": "REG_SZ",
  "value_data": "C:\\ProgramData\\WindowsUpdate\\update.exe",
  "value_data_len": 42,
  "is_persistence_key": true,
  "persistence_type": "autorun",
  "is_launchable": true,
  "is_ifeo": false,
  "ifeo_target": "",
  "severity": "high",
  "tags": ["persistence", "autorun", "registry_modification"]
}
```

---

### 3.7 ProcessAccess Event — LSASS Access (ETW Kernel-Process Event 13/14)

```cpp
// agent/include/telemetry/process_access.h
#pragma once
#include "base.h"

struct ProcessAccessEvent : public BaseEvent {
    // Access details
    uint32_t targetPid;
    std::string targetProcessName; // "lsass.exe"
    std::string targetProcessPath;
    uint32_t accessRights;         // Hex: 0x1410 (PROCESS_VM_READ)
    std::string accessRightsStr;   // "PROCESS_VM_READ|PROCESS_QUERY_INFO"
    
    // Classification
    bool isLsassAccess;            // Target là lsass.exe
    bool isCredentialDump;         // Rights đủ để dump credentials
    std::string callStack;         // Top call stack frames (nếu ETW)
};
```

---

## 4. Alert Event Schema — Output của Inference Engine

```cpp
// agent/include/telemetry/alert.h
#pragma once
#include <string>
#include <vector>
#include <chrono>

// AlertEvent là output cuối cùng khi agent phát hiện threat
struct AlertEvent {
    // Alert identity
    std::string alertId;
    std::chrono::system_clock::time_point createdAt;
    
    // Threat assessment
    float threatScore;           // [0.0, 1.0]
    std::string threatLevel;     // "HIGH"/"CRITICAL"
    float confidence;            // Model confidence
    
    // MITRE ATT&CK mapping
    std::vector<std::string> mitreTactics;     // ["Execution", "Persistence"]
    std::vector<std::string> mitreTechniques;   // ["T1059.001", "T1547.001"]
    
    // Evidence
    std::string triggerEventId;   // EventID gây ra alert
    std::vector<std::string> processChain;      // ["winword.exe→powershell.exe→rundll32.exe"]
    std::vector<std::string> indicators;        // ["encoded_ps", "lolbin", "c2_beacon"]
    
    // Response taken
    std::vector<std::string> actionsTaken;      // ["kill_process", "alert"]
    
    // Raw event snapshot (được serialize thành JSON string)
    std::string triggerEventJson;
};
```

---

## 5. SQLite Storage Schema

```sql
-- Bảng lưu raw events (WAL mode để tránh lock)
CREATE TABLE events (
    id          TEXT PRIMARY KEY,   -- UUID
    timestamp   INTEGER NOT NULL,   -- Unix nanoseconds
    category    TEXT NOT NULL,      -- "process", "file", etc.
    event_type  TEXT NOT NULL,      -- "ProcessCreate", etc.
    pid         INTEGER NOT NULL,
    ppid        INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    severity    TEXT DEFAULT 'info',
    threat_score REAL,              -- NULL nếu chưa infer
    payload     TEXT NOT NULL,      -- Full JSON event
    created_at  INTEGER DEFAULT (strftime('%s','now'))
);

CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX idx_events_pid ON events(pid);
CREATE INDEX idx_events_severity ON events(severity) WHERE severity != 'info';

-- Bảng alerts
CREATE TABLE alerts (
    alert_id        TEXT PRIMARY KEY,
    created_at      INTEGER NOT NULL,
    threat_score    REAL NOT NULL,
    threat_level    TEXT NOT NULL,
    trigger_event_id TEXT REFERENCES events(id),
    process_chain   TEXT,           -- JSON array
    actions_taken   TEXT,           -- JSON array
    payload         TEXT NOT NULL   -- Full AlertEvent JSON
);

-- Bảng process cache (behavior graph persistence khi restart)
CREATE TABLE process_cache (
    pid         INTEGER PRIMARY KEY,
    ppid        INTEGER,
    name        TEXT,
    path        TEXT,
    start_time  INTEGER,
    end_time    INTEGER,
    depth       INTEGER DEFAULT 0
);

-- PRAGMA tối ưu
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -8000;   -- 8MB page cache
PRAGMA temp_store = MEMORY;
```

---

## 6. Event Priority & Throughput

| Event Type | Priority | Estimated Volume (idle) | Max Burst |
|---|---|---|---|
| ProcessCreate | HIGH | 5-20 events/min | 200/min |
| ProcessTerminate | MEDIUM | 5-20 events/min | 200/min |
| FileWrite | HIGH | 50-200 events/min | 10,000/min (ransomware) |
| FileCreate | MEDIUM | 20-100 events/min | 5,000/min |
| NetworkConnect | HIGH | 10-100 events/min | 500/min |
| DNSQuery | MEDIUM | 20-200 events/min | 1,000/min |
| RegistrySet | MEDIUM | 5-50 events/min | 500/min |
| ProcessAccess | HIGH | 1-10 events/min | 100/min |

**Ring Buffer Sizing**:
```
Peak burst scenario (ransomware): 10,000 FileWrite + 500 Network + 200 Process
= ~11,000 events/min = ~185 events/sec
Ring buffer 65,536 slots → covers 5-6 minutes of peak burst
```

---

## 7. Telemetry Architecture Notes
Hệ thống sử dụng các Kernel Providers mặc định thông qua ETW để tối ưu hiệu suất, không cần cấu hình file XML trung gian như các giải pháp truyền thống. Cấu hình các providers được quản lý động qua `agent_config.json`.

---

## 8. Cấu hình Agent (agent_config.json)

File cấu hình kiểm soát trạng thái kích hoạt của từng Collector module và các tham số vận hành của Agent. Agent đọc file này khi khởi động để đăng ký động các Collector (Dynamic Collector Registration).

### 8.1 Schema

```json
{
  "agent_id": "edr-agent-001",
  "agent_version": "1.0.0",
  "model_path": "models/edr_model.onnx",
  "features_config_path": "configs/features_config.json",
  "response_policy_path": "configs/response_policy.json",
  "collectors": {
    "process": {
      "enabled": true,
      "provider_guid": "22c607dd-8a81-40c0-b57e-dc0d05931d74",
      "keywords": "0x10",
      "comment": "Microsoft-Windows-Kernel-Process — Event 1 (ProcessStart), Event 2 (ProcessStop), Event 5 (ImageLoad)"
    },
    "process_access": {
      "enabled": true,
      "provider_guid": "22c607dd-8a81-40c0-b57e-dc0d05931d74",
      "keywords": "0x20",
      "comment": "Microsoft-Windows-Kernel-Process — Event 13 (OpenProcessHandle), Event 14 (DuplicateProcessHandle)"
    },
    "file": {
      "enabled": false,
      "provider_guid": "edd08927-c37b-4de1-ad0f-51892c3c1272",
      "keywords": "0x10",
      "comment": "Microsoft-Windows-Kernel-File — Event 64 (FileCreate), Event 69 (FileDelete)"
    },
    "network": {
      "enabled": false,
      "provider_guid": "7dd27088-cc2c-47a2-ba64-db83f9958a3a",
      "keywords": "0x40",
      "comment": "Microsoft-Windows-Kernel-Network — Event 10 (TcpIp/Connect)"
    },
    "registry": {
      "enabled": true,
      "provider_guid": "70eb4f03-c1de-4f73-a051-33d13d5413bd",
      "keywords": "0x1",
      "comment": "Microsoft-Windows-Kernel-Registry — Event 1 (CreateKey), Event 5 (SetValueKey)"
    }
  },
  "sliding_window_seconds": [5, 30, 300],
  "ring_buffer_size": 65536,
  "log_level": "INFO"
}
```

### 8.2 Hành vi khi một Collector bị tắt

```
Collector bị tắt → Feature Engine không nhận được event từ nguồn đó
       │
       ▼
Khi vectorization được gọi (Trigger Event xảy ra):
  • Đặc trưng Binary/Count (ví dụ: lsass_access, net_outbound_count_30s)
    → Gán giá trị mặc định: 0.0 ("Không có hành vi quan sát được")
  • Đặc trưng Float/Score (ví dụ: beacon_score, max_file_entropy_30s)
    → Gán giá trị mặc định: -1.0 ("Không có thông tin")

Lý do dùng -1.0 cho Float thay vì 0.0:
  → Phân biệt được "entropy = 0.0" (file hoàn toàn đồng nhất, rất hiếm)
     với "entropy = -1.0" (không thu thập được dữ liệu file)
  → Mô hình LightGBM được train với cả hai trường hợp để học cách xử lý
```

---

## 9. Cấu hình Phiên ETW thô (etw_session_config.xml)

Cấu hình dưới đây được dùng để định nghĩa các ETW Providers sẽ đăng ký lắng nghe trong EDR Agent. Chúng ta thiết lập Keyword và Level lọc nhiễu trực tiếp từ tầng nhân (Kernel-space) nhằm tối ưu hiệu năng tối đa.

```xml
<?xml version="1.0" encoding="utf-8"?>
<EtwSessionConfig SessionName="EDR_Telemetry_Session">
  <Providers>
    <!-- Microsoft-Windows-Kernel-Process (GUID: 22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716) -->
    <!-- Keywords: 0x10 (WINEVENT_KEYWORD_PROCESS), 0x20 (WINEVENT_KEYWORD_THREAD), 0x40 (WINEVENT_KEYWORD_IMAGE) -->
    <!-- Events: Event 1 (Start), Event 2 (Stop), Event 5 (ImageLoad), Event 13/14 (HandleOpen/Duplicate) -->
    <Provider Guid="22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716" MatchAnyKeyword="0x70" Level="4" />

    <!-- Microsoft-Windows-Kernel-File (GUID: edd08927-9cc4-4e65-b970-c2560fb5c289) -->
    <!-- Keywords: 0x10 (WINEVENT_KEYWORD_FILE) -->
    <!-- Events: Event 64 (Create), Event 69 (Delete) -->
    <Provider Guid="edd08927-9cc4-4e65-b970-c2560fb5c289" MatchAnyKeyword="0x10" Level="4" />

    <!-- Microsoft-Windows-Kernel-Network (GUID: 7dd42a49-5329-4832-8dfd-43d979153a88) -->
    <!-- Keywords: 0x40 (WINEVENT_KEYWORD_TCPIP) -->
    <!-- Events: Event 10 (TcpIp/Connect) -->
    <Provider Guid="7dd42a49-5329-4832-8dfd-43d979153a88" MatchAnyKeyword="0x40" Level="4" />

    <!-- Microsoft-Windows-Kernel-Registry (GUID: 70eb4f03-c1de-4f73-a051-33d13d5413bd) -->
    <!-- Keywords: 0x1 (WINEVENT_KEYWORD_REGISTRY) -->
    <!-- Events: Event 1 (CreateKey), Event 5 (SetValueKey) -->
    <Provider Guid="70eb4f03-c1de-4f73-a051-33d13d5413bd" MatchAnyKeyword="0x1" Level="4" />
  </Providers>
</EtwSessionConfig>
```

### 9.1 Khởi động và cấu hình phiên ETW bằng `logman`

Để khởi động phiên ghi log ETW thô và lưu trực tiếp ra file cấu hình trên đĩa phục vụ việc phân tích offline/huấn luyện, ta sử dụng lệnh:

```powershell
# 1. Tạo Trace Session mới
logman create trace EDR_Telemetry_Session -ow -o C:\EDR\telemetry.etl

# 2. Đăng ký các Providers và thiết lập Keyword Filter (0x10, 0x40, 0x1...) ở mức Kernel
logman update trace EDR_Telemetry_Session -p "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}" 0x70 4
logman update trace EDR_Telemetry_Session -p "{edd08927-9cc4-4e65-b970-c2560fb5c289}" 0x10 4
logman update trace EDR_Telemetry_Session -p "{7dd42a49-5329-4832-8dfd-43d979153a88}" 0x40 4
logman update trace EDR_Telemetry_Session -p "{70eb4f03-c1de-4f73-a051-33d13d5413bd}" 0x1 4

# 3. Bắt đầu phiên thu thập sự kiện
logman start EDR_Telemetry_Session

# 4. Khi kết thúc quá trình thu thập sự kiện để train AI, dừng phiên log
logman stop EDR_Telemetry_Session
```
```
