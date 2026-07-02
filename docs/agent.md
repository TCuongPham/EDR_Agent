# Agent.md — Đặc tả Kỹ thuật Cốt lõi EDR Agent
## Chi tiết Luồng Xử lý & Kiến trúc Phần mềm (Phiên bản C++ Thuần)

> **Phiên bản**: v2.0 | **Ngày**: 2026-06-07  
> **Mục đích**: Đặc tả kỹ thuật chi tiết để lập trình viên implement Agent bằng 100% C++ (Modern C++17/C++20)

---

## 1. Tổng quan Luồng Xử lý (End-to-End Flow)

```
  OS Kernel Events
       │
       │ ETW / Minifilter Callback / WFP Hook
       ▼
┌──────────────────────────────────────────────────────────────────────┐
│  [LAYER 1] COLLECTOR — Thu thập event thô từ OS                      │
│                                                                      │
│  ProcessCollector  FileCollector  NetworkCollector  RegistryCollector│
│       │                 │               │                   │        │
│       └─────────────────┴───────────────┴───────────────────┘        │
│                                 │                                    │
│                   RawEvent (C++ struct)                              │
└─────────────────────────────────┬────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│  [LAYER 2] PIPELINE — Normalize, Buffer, Enrich                      │
│                                                                      │
│  Normalizer → NormalizedEvent → RingBuffer (Mutex-based SafeQueue)   │
│       │                                                              │
│       Thêm context: username, parent process name, depth             │
└─────────────────────────────────┬────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│  [LAYER 3] FEATURE EXTRACTION — Trích xuất đặc trưng                 │
│                                                                      │
│  ┌───────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  ProcessLineage   │  │  SlidingWindow   │  │  EntropyCalc     │  │
│  │  Graph (Adj.List) │  │  Aggregator      │  │  Shannon H(X)    │  │
│  └───────────────────┘  └──────────────────┘  └──────────────────┘  │
│                    │                                                 │
│              FeatureVector [f1, f2, ..., fn] (std::vector<float>)   │
└─────────────────────────────────┬────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│  [LAYER 4] TIERED INFERENCE — Phán đoán phân tầng                    │
│                                                                      │
│  Tier-1: Rule Engine & Whitelist Filter                              │
│    │ → CLEAN: discard (không tốn CPU inference)                      │
│    │ → UNKNOWN: pass to Tier-2                                       │
│    │ → CRITICAL: immediate alert (IOC match)                         │
│                                                                      │
│  Tier-2: ML Model Inference (ONNX Runtime C++ API)                   │
│    │ → threat_score ∈ [0.0, 1.0]                                     │
│    │ → score < 0.3: BENIGN                                           │
│    │ → 0.3 ≤ score < 0.7: SUSPICIOUS (log + monitor)                 │
│    │ → score ≥ 0.7: MALICIOUS → Tier-3 hoặc Response                │
│                                                                      │
│  Tier-3: Behavioral Graph Correlation (Context Enrichment)           │
│    │ → Kiểm tra Process Lineage Graph                                │
│    │ → Tìm pattern nguy hiểm (Office→PS→Network, LSASS access, ...)  │
│    └ → Final Score = max(ML score, graph_score) × context_weight    │
└─────────────────────────────────┬────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│  [LAYER 5] RESPONSE ENGINE — Hành động phản hồi                      │
│                                                                      │
│  Dựa trên response_policy.json (được đọc bởi nlohmann/json):         │
│  • score ≥ 0.95 → Kill Process + Block Network + Alert               │
│  • score ≥ 0.70 → Alert + Log forensic snapshot                     │
│  • score ≥ 0.50 → Log + Send to backend                             │
│  • score < 0.50 → Discard                                            │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer 1: Collector — Thu thập Event

### 2.1 ETW Consumer Architecture (C++)

Sử dụng thư viện Windows API tiêu chuẩn (`evntrace.h` và `tdh.h`) để lắng nghe các sự kiện hệ thống trực tiếp từ nhân Windows.

```cpp
// agent/include/common.h
#pragma once
#include <stdint.h>

enum class EventType : uint8_t {
    EventProcessCreate = 0,
    EventProcessTerminate,
    EventRegistrySet,
    EventRegistryCreate,
    EventProcessAccess
};

// RawEvent là struct thô nhận từ OS — Sử dụng fixed-size arrays để tối ưu bộ nhớ
struct RawEvent {
    int64_t timestamp;     // Unix epoch in nanoseconds hoặc Windows FileTime
    EventType eventType;
    uint32_t pid;
    uint32_t ppid;
    uint32_t tid;
    uint32_t sessionId;

    // Process fields (valid khi EventType == EventProcessCreate/Terminate/Access)
    char processName[260];
    char commandLine[2048];
    char imagePath[260];

    // Registry fields
    char regKeyPath[512];
    char regValue[256];

    // ProcessAccess fields
    uint32_t targetPid;
    uint32_t accessRights;
};
```

```cpp
// agent/include/collector.h
#pragma once
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>
#include <functional>
#include <unordered_map>
#include <memory>
#include <iostream>
#include <fstream>
#include "common.h"
#include "nlohmann/json.hpp"

// Interface cho các Collector module
class ICollector {
public:
    virtual ~ICollector() = default;
    virtual bool Start() = 0;
    virtual void Stop() = 0;
    virtual std::string GetName() const = 0;
};

class ETWConsumer : public ICollector {
private:
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    EVENT_TRACE_PROPERTIES* m_properties = nullptr;
    std::wstring m_sessionName;
    std::string m_name;
    std::vector<std::pair<std::wstring, uint64_t>> m_providers; // List of GUID + Keyword Mask pairs
    std::function<void(const RawEvent&)> m_callback;
    bool m_isRunning = false;

    void SetupProperties();

public:
    ETWConsumer(const std::wstring& sessionName, const std::string& name, 
                const std::vector<std::pair<std::wstring, uint64_t>>& providers,
                std::function<void(const RawEvent&)> callback)
        : m_sessionName(sessionName), m_name(name), m_providers(providers), m_callback(callback) {}
    ~ETWConsumer() override { Stop(); }

    bool Start() override;
    void Stop() override;
    std::string GetName() const override { return m_name; }
    
    // Callback xử lý event thô từ ETW
    static void WINAPI EventRecordCallback(PEVENT_RECORD eventRecord);
};
```

### 2.3 CollectorRegistry (Đăng ký Collector Động)

Lớp quản lý các Collector, đọc cấu hình `agent_config.json` khi khởi động để chỉ bật các Collector được cấu hình `enabled: true`.

```cpp
// agent/include/collector_registry.h
#pragma once
#include <unordered_map>
#include <memory>
#include <string>
#include <fstream>
#include <iostream>
#include "collector.h"
#include "nlohmann/json.hpp"

class CollectorRegistry {
private:
    std::unordered_map<std::string, std::shared_ptr<ICollector>> m_collectors;

public:
    void RegisterCollector(std::shared_ptr<ICollector> collector) {
        if (collector) {
            m_collectors[collector->GetName()] = collector;
        }
    }

    bool LoadConfigAndStart(const std::string& configPath) {
        std::ifstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[CollectorRegistry] Failed to open agent_config.json" << std::endl;
            return false;
        }

        nlohmann::json j;
        file >> j;

        std::cout << "[CollectorRegistry] Dynamic registration starting (Agent ID: " 
                  << j.value("agent_id", "unknown") << ")" << std::endl;

        for (auto& [name, col] : m_collectors) {
            bool enabled = false;
            // Kiểm tra config, nếu không tìm thấy mặc định là false để an toàn
            if (j.contains("collectors") && j["collectors"].contains(name)) {
                enabled = j["collectors"][name]["enabled"].get<bool>();
            }

            if (enabled) {
                if (col->Start()) {
                    std::cout << "[CollectorRegistry] Started collector: " << name << std::endl;
                } else {
                    std::cerr << "[CollectorRegistry] Failed to start collector: " << name << std::endl;
                }
            } else {
                std::cout << "[CollectorRegistry] Disabled collector: " << name << std::endl;
            }
        }
        return true;
    }

    void StopAll() {
        for (auto& [name, col] : m_collectors) {
            std::cout << "[CollectorRegistry] Stopping collector: " << name << std::endl;
            col->Stop();
        }
    }
};
```


---

## 3. Layer 2: Pipeline — Normalize & Buffer

### 3.1 Event Normalizer

```cpp
// agent/include/normalized_event.h
#pragma once
#include <string>
#include <chrono>
#include <unordered_map>
#include <any>

struct NormalizedEvent {
    std::string id;         // UUID v4
    std::chrono::system_clock::time_point timestamp;
    std::string eventType;  // "ProcessCreate", "FileWrite", etc.
    
    // Process context
    uint32_t pid;
    uint32_t ppid;
    std::string processName;
    std::string processPath;
    std::string commandLine;
    std::string userName;
    uint32_t sessionId;
    
    // Event-specific fields
    std::unordered_map<std::string, std::any> fields;
    
    // Enriched fields
    std::string parentName;
    bool isSystem;
    int depth;
};
```

```cpp
// agent/src/pipeline/normalizer.cpp
#include "normalized_event.h"
#include "common.h"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>

class Normalizer {
private:
    std::unordered_map<uint32_t, std::string> m_processCache;

    std::string GenerateUUID() {
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

    std::string ToLower(std::string str) {
        std::transform(str.begin(), str.end(), str.begin(), ::tolower);
        return str;
    }

public:
    std::shared_ptr<NormalizedEvent> Normalize(const RawEvent& raw) {
        auto evt = std::make_shared<NormalizedEvent>();
        evt->id = GenerateUUID();
        evt->timestamp = std::chrono::system_clock::now();
        evt->pid = raw.pid;
        evt->ppid = raw.ppid;
        evt->sessionId = raw.sessionId;

        evt->processName = ToLower(raw.processName);
        evt->processPath = raw.imagePath;
        evt->commandLine = raw.commandLine;

        if (raw.eventType == EventType::EventProcessCreate) {
            evt->eventType = "ProcessCreate";
            m_processCache[raw.pid] = evt->processName;
            if (m_processCache.count(raw.ppid)) {
                evt->parentName = m_processCache[raw.ppid];
            }
        } 
        else if (raw.eventType == EventType::EventProcessTerminate) {
            evt->eventType = "ProcessTerminate";
            if (m_processCache.count(raw.pid)) {
                m_processCache.erase(raw.pid);
            }
        }
        else if (raw.eventType == EventType::EventRegistrySet) {
            evt->eventType = "RegistrySet";
            evt->fields["keyPath"] = std::string(raw.regKeyPath);
            evt->fields["valueName"] = std::string(raw.regValue);
        }
        else if (raw.eventType == EventType::EventProcessAccess) {
            evt->eventType = "ProcessAccess";
            evt->fields["targetPid"] = raw.targetPid;
            evt->fields["accessRights"] = raw.accessRights;
        }
        
        return evt;
    }
};
```

### 3.2 Thread-Safe Event Queue (Hàng đợi an toàn cho Agent)

Trong C++, ta cài đặt hàng đợi bằng `std::queue` được bảo vệ bằng `std::mutex` và `std::condition_variable` để tránh hiện tượng busy waiting (không tốn CPU khi không có event).

```cpp
// agent/include/ringbuffer.h
#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include "normalized_event.h"

class RingBuffer {
private:
    static const size_t RingBufferSize = 65536; // 64K events
    std::queue<std::shared_ptr<NormalizedEvent>> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    size_t m_maxSize;

public:
    RingBuffer(size_t maxSize = RingBufferSize) : m_maxSize(maxSize) {}

    bool Push(std::shared_ptr<NormalizedEvent> evt) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_maxSize) {
            return false; // Queue đầy — drop event
        }
        m_queue.push(evt);
        m_cond.notify_one();
        return true;
    }

    std::shared_ptr<NormalizedEvent> Pop() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cond.wait(lock, [this]() { return !m_queue.empty(); }); // Ngủ nếu queue rỗng
        
        auto evt = m_queue.front();
        m_queue.pop();
        return evt;
    }

    size_t Size() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }
};
```

---

## 4. Layer 3: In-Memory Behavior Graph

### 4.1 Process Lineage Graph

Sử dụng `std::unordered_map` làm cấu trúc lưu trữ nút cây tiến trình và được bảo vệ bằng `std::shared_mutex` (C++17) cho phép nhiều luồng đọc đồng thời và chỉ khóa độc quyền khi thêm tiến trình mới.

```cpp
// agent/include/lineage_graph.h
#pragma once
#include <unordered_map>
#include <vector>
#include <string>
#include <shared_mutex>
#include <chrono>
#include <memory>

struct ProcessNode {
    uint32_t pid;
    uint32_t ppid;
    std::string name;
    std::string path;
    std::string commandLine;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    int depth = 0;
    
    // Dynamic attributes for generic behavior correlation (Stage-3 / Tier-3)
    std::unordered_map<std::string, std::string> attributes;
    std::unordered_map<std::string, float> metrics;

    void SetAttribute(const std::string& key, const std::string& val) {
        attributes[key] = val;
    }
    std::string GetAttribute(const std::string& key) const {
        auto it = attributes.find(key);
        return it != attributes.end() ? it->second : "";
    }
    
    // Legacy / Convenience flags mapping to dynamic attributes
    bool hasNetworkConn() const { return metrics.count("network_conn_count") && metrics.at("network_conn_count") > 0; }
    bool hasFileModify() const { return metrics.count("file_modify_count") && metrics.at("file_modify_count") > 0; }
    bool hasRegistryWrite() const { return metrics.count("registry_write_count") && metrics.at("registry_write_count") > 0; }
    bool hasLSASSAccess() const { return GetAttribute("lsass_access") == "1"; }
};

class BehaviorGraph {
private:
    std::shared_mutex m_mutex;
    std::unordered_map<uint32_t, std::shared_ptr<ProcessNode>> m_nodes;
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_children; // PPID -> list of PIDs (Adjacency List)
    size_t m_maxNodes;

    void EvictOldest() {
        // Eviction logic để giải phóng bộ nhớ RAM
    }

public:
    BehaviorGraph(size_t maxNodes = 10000) : m_maxNodes(maxNodes) {}

    void AddProcess(std::shared_ptr<ProcessNode> node) {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        if (m_nodes.size() >= m_maxNodes) {
            EvictOldest();
        }
        
        // Tính độ sâu của cây
        if (m_nodes.count(node->ppid)) {
            node->depth = m_nodes[node->ppid]->depth + 1;
        }
        
        m_nodes[node->pid] = node;
        m_children[node->ppid].push_back(node->pid);
    }

    void RemoveProcess(uint32_t pid) {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        
        // Khi nhận được sự kiện ProcessStop (ETW Event 2), dọn dẹp node để tránh rò rỉ bộ nhớ
        // và giải quyết bài toán tái sử dụng PID (PID Recycling).
        if (m_nodes.count(pid)) {
            auto node = m_nodes[pid];
            node->endTime = std::chrono::system_clock::now();
            
            // Xóa khỏi danh sách con của cha nó
            uint32_t ppid = node->ppid;
            if (m_children.count(ppid)) {
                auto& childList = m_children[ppid];
                childList.erase(std::remove(childList.begin(), childList.end(), pid), childList.end());
            }
            
            m_nodes.erase(pid);
            m_children.erase(pid); // Xóa danh sách con của chính nó vì nó đã chết
            std::cout << "[BehaviorGraph] Cleaned up exited process PID: " << pid << " (PID recycled)" << std::endl;
        }
    }

    std::vector<std::shared_ptr<ProcessNode>> GetLineage(uint32_t pid) {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        std::vector<std::shared_ptr<ProcessNode>> chain;
        uint32_t current = pid;
        
        for (int i = 0; i < 50; ++i) { // Giới hạn max 50 level để chống loop
            if (m_nodes.find(current) != m_nodes.end()) {
                auto node = m_nodes[current];
                chain.insert(chain.begin(), node); // Prepend
                if (node->ppid == 0 || node->ppid == current) {
                    break;
                }
                current = node->ppid;
            } else {
                break;
            }
        }
        return chain;
    }

    bool MatchPattern(uint32_t pid, const std::vector<std::string>& pattern) {
        auto lineage = GetLineage(pid);
        if (lineage.size() < pattern.size()) return false;

        // Trượt window của pattern trên lineage để match
        for (size_t i = 0; i <= lineage.size() - pattern.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < pattern.size(); ++j) {
                if (lineage[i + j]->name != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }
};
```

---

## 5. Layer 3: Feature Extraction Engine

### 5.1 Sliding Window Aggregator

```cpp
// agent/include/sliding_window.h
#pragma once
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>
#include <memory>
#include "normalized_event.h"

struct WindowBucket {
    uint32_t pid;
    std::chrono::system_clock::time_point windowStart;
    std::chrono::seconds duration;

    uint32_t childSpawnCount = 0;
    uint32_t regWriteCount = 0;
    bool runKeyAccess = false;
};

class SlidingWindowAggregator {
private:
    std::mutex m_mutex;
    std::unordered_map<uint32_t, std::vector<std::shared_ptr<WindowBucket>>> m_windows;
    std::vector<std::chrono::seconds> m_durations;

public:
    SlidingWindowAggregator() {
        m_durations = { std::chrono::seconds(5), std::chrono::seconds(30), std::chrono::seconds(300) };
    }

    void Update(std::shared_ptr<NormalizedEvent> evt) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t pid = evt->pid;
        auto now = evt->timestamp;

        // Khởi tạo các bucket thời gian nếu chưa có
        if (m_windows.find(pid) == m_windows.end()) {
            m_windows[pid] = {
                std::make_shared<WindowBucket>(WindowBucket{pid, now, m_durations[0]}),
                std::make_shared<WindowBucket>(WindowBucket{pid, now, m_durations[1]}),
                std::make_shared<WindowBucket>(WindowBucket{pid, now, m_durations[2]})
            };
        }

        for (size_t i = 0; i < 3; ++i) {
            auto bucket = m_windows[pid][i];
            
            // Nếu vượt quá thời gian của cửa sổ trượt -> Reset bucket
            if (now - bucket->windowStart > bucket->duration) {
                bucket->windowStart = now;
                bucket->childSpawnCount = 0;
                bucket->regWriteCount = 0;
                bucket->runKeyAccess = false;
            }

            if (evt->eventType == "ProcessCreate") {
                bucket->childSpawnCount++;
            } else if (evt->eventType == "RegistrySet") {
                bucket->regWriteCount++;
                try {
                    if (evt->fields.count("isPersistenceKey")) {
                        bucket->runKeyAccess = std::any_cast<bool>(evt->fields.at("isPersistenceKey"));
                    }
                } catch (...) {}
            }
        }
    }

    std::vector<float> GetFeatureVector(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<float> features(27, 0.0f);
        
        if (m_windows.find(pid) == m_windows.end()) {
            return features;
        }

        auto& buckets = m_windows[pid];
        size_t idx = 0;
        
        for (const auto& b : buckets) {
            if (idx + 3 > 27) break;
            features[idx++] = static_cast<float>(b->childSpawnCount);
            features[idx++] = static_cast<float>(b->regWriteCount);
            features[idx++] = b->runKeyAccess ? 1.0f : 0.0f;
        }
        
        return features;
    }
};
```

### 5.2 Dynamic Feature Registry (Đăng ký Đặc trưng Động)

Lớp quản lý các Extractor, cho phép định nghĩa cấu hình động qua `features_config.json`. Khi một Collector bị tắt, FeatureRegistry tự động impute giá trị mặc định (0.0 cho count/binary, -1.0 cho float) mà không làm lệch vector đầu vào của ONNX model.

```cpp
// agent/include/features_registry.h
#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <fstream>
#include <iostream>
#include "normalized_event.h"
#include "nlohmann/json.hpp"

class IFeatureExtractor {
public:
    virtual ~IFeatureExtractor() = default;
    virtual float Extract(uint32_t pid, std::shared_ptr<NormalizedEvent> evt) = 0;
    virtual std::string GetName() const = 0;
};

struct FeatureConfig {
    int index;
    std::string name;
    std::string type;
    float defaultValue;
    std::string namespaceName;
};

class FeatureRegistry {
private:
    std::unordered_map<std::string, std::shared_ptr<IFeatureExtractor>> m_extractors;
    std::vector<FeatureConfig> m_activeFeatures;

public:
    void RegisterExtractor(std::shared_ptr<IFeatureExtractor> extractor) {
        if (extractor) {
            m_extractors[extractor->GetName()] = extractor;
        }
    }

    bool LoadConfig(const std::string& configPath) {
        std::ifstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[FeatureRegistry] Failed to open features_config.json" << std::endl;
            return false;
        }

        nlohmann::json j;
        file >> j;

        m_activeFeatures.clear();
        for (const auto& item : j["features"]) {
            FeatureConfig cfg;
            cfg.index = item["index"];
            cfg.name = item["name"];
            cfg.type = item["type"];
            cfg.defaultValue = item["default"];
            cfg.namespaceName = item["namespace"];
            m_activeFeatures.push_back(cfg);
        }

        // Sắp xếp theo index tăng dần để đảm bảo thứ tự vector khớp với input của model ONNX
        std::sort(m_activeFeatures.begin(), m_activeFeatures.end(), 
            [](const FeatureConfig& a, const FeatureConfig& b) {
                return a.index < b.index;
            }
        );

        std::cout << "[FeatureRegistry] Loaded " << m_activeFeatures.size() 
                  << " features from " << configPath << std::endl;
        return true;
    }

    std::vector<float> Vectorize(uint32_t pid, std::shared_ptr<NormalizedEvent> evt) {
        std::vector<float> featureVector;
        featureVector.reserve(m_activeFeatures.size());

        for (const auto& cfg : m_activeFeatures) {
            // Nếu extractor tương ứng được đăng ký và collector liên quan hoạt động
            if (m_extractors.count(cfg.name)) {
                featureVector.push_back(m_extractors[cfg.name]->Extract(pid, evt));
            } else {
                // Default Value Imputation: Gán giá trị mặc định nếu collector bị tắt
                featureVector.push_back(cfg.defaultValue);
            }
        }
        return featureVector;
    }

    size_t GetFeatureCount() const {
        return m_activeFeatures.size();
    }
};
```

### 5.3 Shannon Entropy Calculator

```cpp
// agent/include/entropy.h
#pragma once
#include <cmath>
#include <vector>
#include <string>
#include <fstream>

class EntropyCalculator {
public:
    static float ShannonEntropy(const std::vector<uint8_t>& data) {
        if (data.empty()) return 0.0f;
        
        size_t freq[256] = {0};
        for (uint8_t b : data) {
            freq[b]++;
        }
        
        double total = static_cast<double>(data.size());
        double entropy = 0.0;
        
        for (size_t count : freq) {
            if (count == 0) continue;
            double p = static_cast<double>(count) / total;
            entropy -= p * log2(p);
        }
        
        return static_cast<float>(entropy);
    }

    // Chỉ đọc tối đa 4KB đầu của file để tránh nghẽn I/O hệ thống
    static float ShannonEntropyPath(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return 0.0f;

        std::vector<uint8_t> buffer(4096);
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        size_t bytesRead = static_cast<size_t>(file.gcount());
        buffer.resize(bytesRead);

        return ShannonEntropy(buffer);
    }
};
```

### 5.4 Cryptographic Hashing Engine (SHA256)

Sử dụng thư viện mã hóa Windows Cryptography API: Next Generation (CNG) (`bcrypt.h`) để tính toán mã băm SHA256 của các tệp tin executable/DLL mới được nạp hoặc tải về. Thiết lập xử lý bất đồng bộ (Thread Pool) và cơ chế bộ nhớ đệm (RAM Cache) để giảm thiểu I/O bottleneck.

```cpp
// agent/include/file_hasher.h
#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <shared_mutex>
#include <future>

#pragma comment(lib, "bcrypt.lib")

class FileHasher {
private:
    std::unordered_map<std::string, std::string> m_hashCache;
    std::shared_mutex m_cacheMutex;
    const size_t MaxCacheSize = 5000;

public:
    FileHasher() = default;

    std::string GetSHA256(const std::string& filePath) {
        // 1. Kiểm tra cache trước để tối ưu hiệu năng
        {
            std::shared_lock<std::shared_mutex> lock(m_cacheMutex);
            auto it = m_hashCache.find(filePath);
            if (it != m_hashCache.end()) {
                return it->second;
            }
        }

        // 2. Tính toán hash trực tiếp
        std::string hash = ComputeSHA256Direct(filePath);
        
        if (!hash.empty()) {
            std::unique_lock<std::shared_mutex> lock(m_cacheMutex);
            if (m_hashCache.size() >= MaxCacheSize) {
                m_hashCache.clear(); // Evict all if cache full
            }
            m_hashCache[filePath] = hash;
        }
        return hash;
    }

    // Chạy tính toán bất đồng bộ qua thread pool (std::async)
    std::future<std::string> GetSHA256Async(const std::string& filePath) {
        return std::async(std::launch::async, &FileHasher::GetSHA256, this, filePath);
    }

private:
    std::string ComputeSHA256Direct(const std::string& filePath) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = 0;
        DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;
        std::string hashHex = "";

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (status < 0) goto cleanup;

        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        if (status < 0) goto cleanup;

        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (status < 0) goto cleanup;

        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        if (!pbHashObject) goto cleanup;

        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (!pbHash) goto cleanup;

        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (status < 0) goto cleanup;

        {
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) goto cleanup;

            std::vector<char> buffer(65536); // 64KB chunks
            while (file.good()) {
                file.read(buffer.data(), buffer.size());
                std::streamsize bytesRead = file.gcount();
                if (bytesRead > 0) {
                    status = BCryptHashData(hHash, (PBYTE)buffer.data(), (ULONG)bytesRead, 0);
                    if (status < 0) goto cleanup;
                }
            }
        }

        status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        if (status < 0) goto cleanup;

        {
            char hexChars[] = "0123456789abcdef";
            hashHex.reserve(cbHash * 2);
            for (DWORD i = 0; i < cbHash; i++) {
                hashHex.push_back(hexChars[pbHash[i] >> 4]);
                hashHex.push_back(hexChars[pbHash[i] & 0x0F]);
            }
        }

    cleanup:
        if (hHash) BCryptDestroyHash(hHash);
        if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
        if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

        return hashHex;
    }
};
```

---

## 6. Layer 4: Tiered Inference Architecture

### 6.1 Tier-1: Rule Engine & Whitelist

```cpp
// agent/include/rule_engine.h
#pragma once
#include <unordered_set>
#include <regex>
#include <string>
#include <memory>
#include "normalized_event.h"

enum class RuleDecision : uint8_t {
    RuleDecisionClean = 0,
    RuleDecisionUnknown,
    RuleDecisionCritical
};

class RuleEngine {
private:
    std::unordered_set<std::string> m_whitelist;
    std::vector<std::regex> m_cmdlineRegex;

public:
    RuleEngine() {
        m_whitelist = {
            "system", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "taskhostw.exe", "searchindexer.exe"
        };
        m_cmdlineRegex = {
            std::regex("-[Ee]nc(odedCommand)?\\s+[A-Za-z0-9+/=]{100,}", std::regex_constants::icase),
            std::regex("-[Ee]xecution[Pp]olicy\\s+[Bb]ypass", std::regex_constants::icase),
            std::regex("(Invoke-WebRequest|IWR|WebClient|DownloadString|DownloadFile)", std::regex_constants::icase),
            std::regex("(procdump|minidump|lsass)", std::regex_constants::icase)
        };
    }

    RuleDecision Evaluate(std::shared_ptr<NormalizedEvent> evt) {
        // 1. Kiểm tra whitelist
        if (m_whitelist.count(evt->processName)) {
            if (evt->fields.count("target_process")) {
                try {
                    std::string target = std::any_cast<std::string>(evt->fields.at("target_process"));
                    if (target.find("lsass") != std::string::npos) {
                        return RuleDecision::RuleDecisionCritical; // Cố tình access LSASS là nguy hiểm
                    }
                } catch (...) {}
            }
            return RuleDecision::RuleDecisionClean;
        }

        // 2. Kiểm tra cmdline regex
        for (const auto& pattern : m_cmdlineRegex) {
            if (std::regex_search(evt->commandLine, pattern)) {
                return RuleDecision::RuleDecisionCritical;
            }
        }

        return RuleDecision::RuleDecisionUnknown;
    }
};
```

### 6.2 Tier-2: ONNX ML Inference (Tích hợp native C++ API)

Không sử dụng wrapper ngoại vi, chúng ta sẽ gọi thư viện của Microsoft trực tiếp bằng ONNX Runtime C++ API.

```cpp
// agent/include/onnx_inferencer.h
#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <onnxruntime_cxx_api.h>

class ONNXInferencer {
private:
    Ort::Env m_env;
    Ort::Session m_session = nullptr;
    std::vector<std::string> m_inputNamesAllocated;
    std::vector<std::string> m_outputNamesAllocated;
    std::vector<const char*> m_inputNames;
    std::vector<const char*> m_outputNames;
    std::vector<int64_t> m_inputShape;

public:
    ONNXInferencer(const std::wstring& modelPath) 
        : m_env(ORT_LOGGING_LEVEL_WARNING, "EDR_AI_Agent") {
        
        Ort::SessionOptions sessionOptions;
        sessionOptions.SetIntraOpNumThreads(1);
        sessionOptions.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        sessionOptions.DisableMemPattern();

        m_session = Ort::Session(m_env, modelPath.c_str(), sessionOptions);

        // Truy vấn động input shape và tên các tensor đầu vào/đầu ra từ ONNX Metadata
        Ort::AllocatorWithDefaultAllocator allocator;
        
        // 1. Get input details
        size_t numInputNodes = m_session.GetInputCount();
        for (size_t i = 0; i < numInputNodes; ++i) {
            auto inputName = m_session.GetInputNameAllocated(i, allocator);
            m_inputNamesAllocated.push_back(inputName.get());
            
            Ort::TypeInfo typeInfo = m_session.GetInputTypeInfo(i);
            auto tensorInfo = typeInfo.GetTensorTypeAndShapeInfo();
            m_inputShape = tensorInfo.GetShape();
            
            // Đảm bảo batch size = 1
            if (!m_inputShape.empty() && m_inputShape[0] < 0) {
                m_inputShape[0] = 1; 
            }
        }
        
        // 2. Get output details
        size_t numOutputNodes = m_session.GetOutputCount();
        for (size_t i = 0; i < numOutputNodes; ++i) {
            auto outputName = m_session.GetOutputNameAllocated(i, allocator);
            m_outputNamesAllocated.push_back(outputName.get());
        }

        // Tạo raw pointers cho Session::Run
        for (const auto& name : m_inputNamesAllocated) m_inputNames.push_back(name.c_str());
        for (const auto& name : m_outputNamesAllocated) m_outputNames.push_back(name.c_str());
    }

    float Infer(const std::vector<float>& features) {
        // Kiểm tra dynamic shape khớp với size đặc trưng truyền vào
        int64_t expectedFeatures = 1;
        for (size_t i = 1; i < m_inputShape.size(); ++i) {
            expectedFeatures *= m_inputShape[i];
        }
        
        if (features.size() != static_cast<size_t>(expectedFeatures)) {
            std::cerr << "[ONNXInferencer] Feature vector dimension mismatch! Model expected " 
                      << expectedFeatures << ", but got " << features.size() << std::endl;
            return 0.0f;
        }

        Ort::MemoryInfo memoryInfo = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        
        // Tạo input tensor từ float vector (không copy dữ liệu)
        Ort::Value inputTensor = Ort::Value::CreateTensor<float>(
            memoryInfo, 
            const_cast<float*>(features.data()), 
            features.size(), 
            m_inputShape.data(), 
            m_inputShape.size()
        );

        // Chạy mô hình
        auto outputTensors = m_session.Run(
            Ort::RunOptions{nullptr}, 
            m_inputNames.data(), &inputTensor, 1, 
            m_outputNames.data(), m_outputNames.size()
        );

        // Lấy xác suất của lớp đầu ra (Output: [P(benign), P(malware_behavior), P(credential_access)])
        // outputTensors[1] chứa float probabilities cho multiclass classification
        float* probabilities = outputTensors[1].GetTensorMutableData<float>();
        
        // Scoring formula cho multiclass:
        // P(benign) * 0.0 + P(malware_behavior) * 0.5 + P(credential_access) * 1.0
        float threatScore = probabilities[1] * 0.5f + probabilities[2] * 1.0f;
        
        return std::clamp(threatScore, 0.0f, 1.0f);
    }
};
```

### 6.3 Tier-3: Behavioral Graph Correlation

```cpp
// agent/include/scorer.h
#pragma once
#include <vector>
#include <string>
#include <memory>
#include "normalized_event.h"

struct ScoringContext {
    std::shared_ptr<NormalizedEvent> event;
    std::vector<float> featureVector;
    float mlScore = 0.0f;
    float graphScore = 0.0f;
    bool patternMatch = false;
    std::vector<std::string> lineage;

    float FinalScore() const {
        float base = mlScore;
        if (patternMatch) base += 0.2f;

        int suspiciousCount = 0;
        if (graphScore > 0.5f) suspiciousCount++;
        if (mlScore > 0.4f) suspiciousCount++;
        if (patternMatch) suspiciousCount++;

        if (suspiciousCount >= 2) {
            base *= 1.3f;
        }

        if (base > 1.0f) base = 1.0f;
        return base;
    }
};

inline std::string ScoreToLevel(float score) {
    if (score < 0.2f) return "BENIGN";
    if (score < 0.4f) return "LOW";
    if (score < 0.6f) return "MEDIUM";
    if (score < 0.8f) return "HIGH";
    return "CRITICAL";
}
```

---

## 7. Layer 5: Response Engine

```cpp
// agent/include/response_handler.h
#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include "scorer.h"
#include "nlohmann/json.hpp" // Sử dụng thư viện json nhẹ của nlohmann

struct PolicyRule {
    float minScore;
    float maxScore;
    std::vector<std::string> actions;
    std::string alertLevel;
};

class ResponseHandler {
private:
    std::vector<PolicyRule> m_rules;

    void SendAlert(const ScoringContext& ctx, float score) {
        std::cout << "[ALERT] Threat detected. Score: " << score 
                  << ", Level: " << ScoreToLevel(score) 
                  << ", Process: " << ctx.event->processName 
                  << " (PID: " << ctx.event->pid << ")" << std::endl;
    }

    bool KillProcess(uint32_t pid) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) return false;
        BOOL result = TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        return result == TRUE;
    }

    void BlockNetworkForProcess(uint32_t pid) {
        // Gọi API Windows Firewall hoặc WFP để chặn kết nối
        std::cout << "[FIREWALL] Blocked network for PID: " << pid << std::endl;
    }

public:
    ResponseHandler(const std::string& policyPath) {
        std::ifstream file(policyPath);
        if (!file.is_open()) return;
        
        nlohmann::json j;
        file >> j;
        
        for (const auto& item : j["rules"]) {
            PolicyRule rule;
            rule.minScore = item["min_score"];
            rule.maxScore = item["max_score"];
            rule.actions = item["actions"].get<std::vector<std::string>>();
            rule.alertLevel = item["alert_level"];
            m_rules.push_back(rule);
        }
    }

    void Handle(const ScoringContext& ctx) {
        float score = ctx.FinalScore();
        
        for (const auto& rule : m_rules) {
            if (score >= rule.minScore && score < rule.maxScore) {
                for (const auto& action : rule.actions) {
                    if (action == "alert") {
                        SendAlert(ctx, score);
                    } else if (action == "kill") {
                        KillProcess(ctx.event->pid);
                    } else if (action == "block") {
                        BlockNetworkForProcess(ctx.event->pid);
                    }
                }
                break;
            }
        }
    }
};
```

---

## 8. Main Agent Orchestrator

Phần điều phối chính chạy các đa luồng xử lý bất đồng bộ sử dụng thư viện luồng chuẩn `std::thread`.

```cpp
// agent/src/main.cpp
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include "collector.h"
#include "collector_registry.h"
#include "ringbuffer.h"
#include "lineage_graph.h"
#include "sliding_window.h"
#include "features_registry.h"
#include "rule_engine.h"
#include "onnx_inferencer.h"
#include "response_handler.h"

std::atomic<bool> g_running(true);

void SignalHandler(int signum) {
    g_running = false;
}

int main() {
    // Xử lý các tín hiệu để tắt chương trình an toàn
    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

    // Khởi tạo các hàng đợi và bộ nhớ đệm
    RingBuffer ringBuffer(65536);
    
    // Khởi tạo components
    auto behaviorGraph = std::make_shared<BehaviorGraph>(10000);
    auto windowAgg = std::make_shared<SlidingWindowAggregator>();
    
    // Đăng ký Feature Registry và nạp cấu hình đặc trưng động
    FeatureRegistry featureRegistry;
    // Đăng ký các feature extractors (MVP ví dụ)
    // featureRegistry.RegisterExtractor(std::make_shared<ChildSpawnCount5sExtractor>(windowAgg));
    // ...
    if (!featureRegistry.LoadConfig("configs/features_config.json")) {
        std::cerr << "[Main] Failed to load features configuration!" << std::endl;
        return -1;
    }

    RuleEngine ruleEngine;
    ONNXInferencer onnxInferencer(L"models/edr_model.onnx");
    ResponseHandler responseHandler("configs/response_policy.json");

    // Khởi tạo và đăng ký các Collector động
    CollectorRegistry collectorRegistry;
    
    // Cấu hình các ETW Providers (Process, File, Network, Registry) cho Session duy nhất
    std::vector<std::pair<std::wstring, uint64_t>> etwProviders = {
        { L"22c607dd-8a81-40c0-b57e-dc0d05931d74", 0x70 }, // Kernel-Process (Process, Thread, Image)
        { L"edd08927-c37b-4de1-ad0f-51892c3c1272", 0x10 }, // Kernel-File (File I/O)
        { L"7dd27088-cc2c-47a2-ba64-db83f9958a3a", 0x40 }, // Kernel-Network (Network Connection)
        { L"70eb4f03-c1de-4f73-a051-33d13d5413bd", 0x1 }   // Kernel-Registry (Registry Modifications)
    };

    // Đăng ký ETW Telemetry Collector hợp nhất
    collectorRegistry.RegisterCollector(std::make_shared<ETWConsumer>(
        L"EDR_Telemetry_Session", "etw_telemetry", etwProviders, [&](const RawEvent& raw) {
            Normalizer normalizer;
            auto normalized = normalizer.Normalize(raw);
            if (normalized) ringBuffer.Push(normalized);
        }
    ));

    // Nạp agent_config.json để bật/tắt các collector động
    if (!collectorRegistry.LoadConfigAndStart("configs/agent_config.json")) {
        std::cerr << "[Main] Failed to load agent configuration!" << std::endl;
        return -1;
    }

    // Thread 2: Main Processing Loop (AI Inference & Graph Analysis)
    std::thread processingThread([&]() {
        while (g_running) {
            auto evt = ringBuffer.Pop(); // Sẽ block luồng nếu không có event
            if (!evt) continue;

            // Xử lý sự kiện ProcessStop (tương ứng với EID 2 ProcessTerminate) để dọn dẹp đồ thị hành vi
            if (evt->eventType == "ProcessStop" || evt->eventType == "ProcessTerminate") {
                behaviorGraph->RemoveProcess(evt->pid);
                continue;
            }

            // Cập nhật Behavior Graph (Tier-3 Correlation)
            auto node = std::make_shared<ProcessNode>();
            node->pid = evt->pid;
            node->ppid = evt->ppid;
            node->name = evt->processName;
            node->commandLine = evt->commandLine;
            node->startTime = evt->timestamp;
            
            // Cập nhật thuộc tính đồ thị động dựa trên thông tin log nhận được
            if (evt->eventType == "ProcessAccess") {
                node->SetAttribute("lsass_access", "1");
            }
            behaviorGraph->AddProcess(node);

            // Cập nhật Sliding Window Aggregator
            windowAgg->Update(evt);

            // Tier-1: Đánh giá nhanh bằng Rule Engine & Whitelist
            RuleDecision decision = ruleEngine.Evaluate(evt);
            if (decision == RuleDecision::RuleDecisionClean) {
                continue; // Bỏ qua không suy luận AI để tối ưu CPU máy trạm
            }

            // Tier-2: Trích xuất đặc trưng động dựa trên features_config.json
            auto features = featureRegistry.Vectorize(evt->pid, evt);
            float mlScore = onnxInferencer.Infer(features);

            // Tier-3: Kiểm tra các mẫu đồ thị liên kết hành vi (Behavioral Graph Correlation)
            auto lineage = behaviorGraph->GetLineage(evt->pid);
            bool patternMatch = false;
            std::vector<std::string> targetPattern = { "winword.exe", "powershell.exe" };
            if (behaviorGraph->MatchPattern(evt->pid, targetPattern)) {
                patternMatch = true;
            }

            // Tính điểm tổng hợp và đưa ra phản hồi phù hợp
            ScoringContext scoringCtx;
            scoringCtx.event = evt;
            scoringCtx.featureVector = features;
            scoringCtx.mlScore = mlScore;
            scoringCtx.patternMatch = patternMatch;
            for (const auto& n : lineage) {
                scoringCtx.lineage.push_back(n->name);
            }

            if (decision == RuleDecision::RuleDecisionCritical || scoringCtx.FinalScore() > 0.5f) {
                responseHandler.Handle(scoringCtx);
            }
        }
    });

    // Chờ dừng hệ thống
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Tắt tất cả collector và cleanup
    collectorRegistry.StopAll();
    if (processingThread.joinable()) processingThread.join();

    std::cout << "EDR Agent stopped gracefully." << std::endl;
    return 0;
}
```

---

## 9. Performance Considerations & Optimization

| Component | Chiến lược tối ưu trong C++ |
|---|---|
| **Ring Buffer** | Sử dụng hàng đợi thread-safe với biến điều kiện (`std::condition_variable`) tránh busy-waiting tốn CPU. |
| **Memory Allocation** | Tận dụng Smart Pointer (`std::shared_ptr`, `std::unique_ptr`) và `std::move` để chuyển ownership, tránh copy data lớn trong Heap. |
| **Behavior Graph** | Sử dụng khóa đọc/ghi đồng thời `std::shared_mutex` thay vì khóa cứng để cải thiện throughput khi có nhiều thread đọc lineage. |
| **ONNX Inference** | Tận dụng thư viện runtime C++ tối ưu đa nhân của Intel/Microsoft, áp dụng mô hình quantize INT8 có dung lượng chỉ dưới 3MB. |
| **Rule Engine** | Cache các đối tượng regex đã biên dịch sẵn trong constructor, tránh biên dịch lại khi lọc sự kiện. |

### Multithreading Architecture (C++ jthread/thread)

```
main thread
│
├── Thread 1: ETWCollector          # Lấy log thô từ ETW (C/C++ Callback)
│   └── push (Normalizer) ────────→ RingBuffer
│                                   
├── Thread 2: AgentProcessing       # Chạy bất đồng bộ
│   ├── behaviorGraph.Update()
│   ├── slidingWindow.Update()
│   ├── ruleEngine.Evaluate()       # Fast path
│   ├── onnxInferencer.Infer()      # Slow path: < 1ms (Native C++ INT8)
│   └── responseHandler.Handle()   
│                                   
└── Background: OS monitor          # SQLite logging (WAL mode)
```

**Ước tính bộ nhớ tiêu hao của bản C++**:
- Thread-safe Queue: `65536 × std::shared_ptr` ≈ 512 KB
- Behavior Graph: `10,000 nodes × 400B` ≈ 4.0 MB (C++ biểu diễn string và map tối ưu hiệu năng bộ nhớ)
- Window Aggregator: `1000 PIDs × 3 buckets × 150B` ≈ 450 KB
- ONNX Model (INT8): ≈ 1-3 MB
- **TỔNG RAM**: **< 15 MB** (Idle) / **< 40 MB** (Active)
- *Nhẹ hơn đáng kể so với các ngôn ngữ quản lý bộ nhớ tự động (GC) do không phải gánh vác runtime và garbage collection overhead.*
