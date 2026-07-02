# Planning.md — Kế hoạch Tổng thể & Kiến trúc Triển khai
## EDR AI Agent: AI/ML Engine tích hợp trực tiếp trên Endpoint

> [!IMPORTANT]
> **Hướng dẫn Biên dịch & Chạy EDR Agent (Yêu cầu chạy CMD/PowerShell với quyền Administrator)**:
> 
> **1. Lệnh Biên dịch (Build):**
> ```powershell
> # Cấu hình và Build dự án bằng CMake sang thư mục build/
> cmake -B build -S .
> cmake --build build --config Release
> ```
> 
> **2. Lệnh Chạy (Run):**
> ```powershell
> # Di chuyển tới thư mục chứa file thực thi vừa biên dịch
> cd D:\Universe\VCS\EDR_AI_Agent\build\agent\Release
> 
> # Khởi chạy Agent với đường dẫn file cấu hình agent_config.json
> .\edr_agent.exe Z:\EDR_AI_Agent\agent\configs\agent_config.json
> ```

> **Phiên bản**: v1.0 | **Ngày**: 2026-06-07  
> **Tác giả**: Cybersecurity Architect & Edge AI Engineer  
> **Phạm vi**: Nghiên cứu & Phát triển cho sinh viên thực tập (từ cơ bản → nâng cao)

---

## 1. Tổng quan Kiến trúc Hệ thống

```
┌──────────────────────────────────────────────────────────────────────┐
│                      ENDPOINT (Windows / Linux)                      │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                   EDR SENSOR LAYER (Ring 0/3)                   │ │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌────────────┐  │ │
│  │  │  Process  │  │   File    │  │ Registry  │  │  Network   │  │ │
│  │  │  Monitor  │  │  Monitor  │  │  Monitor  │  │  Monitor   │  │ │
│  │  │(ETW/WMI)  │  │(Minifilter│  │(RegMon/   │  │(WFP/Pcap)  │  │ │
│  │  │           │  │ Driver)   │  │ ETW)      │  │            │  │ │
│  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬──────┘  │ │
│  └────────┼──────────────┼──────────────┼──────────────┼──────────┘ │
│           └──────────────┴──────────────┴──────────────┘            │
│                                    │                                 │
│                                    ▼                                 │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              TELEMETRY PIPELINE (Ring 3 — User Space)           │ │
│  │   Event Normalizer → JSON Struct → In-memory Ring Buffer        │ │
│  └─────────────────────────────┬───────────────────────────────────┘ │
│                                │                                     │
│                                ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              FEATURE EXTRACTION ENGINE                          │ │
│  │   Process Lineage Graph │ Sliding Window │ Entropy Calc         │ │
│  └─────────────────────────────┬───────────────────────────────────┘ │
│                                │                                     │
│                                ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              TIERED AI INFERENCE ENGINE                         │ │
│  │   Tier-1: Rule/Whitelist Filter (Fast-path, agent_config.json)  │ │
│  │   → Tier-2: LightGBM Multiclass Model (ONNX, Dynamic Shape)    │ │
│  │   → Tier-3: Behavioral Graph Correlation (Generic Node, K-V)   │ │
│  └─────────────────────────────┬───────────────────────────────────┘ │
│                                │                                     │
│                                ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              RESPONSE ENGINE                                    │ │
│  │   Alert │ Kill Process │ Report       │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
              ┌─────────────────────────────┐
              │    BACKEND (Optional/Async)  │
              │  Log Aggregation │ Dashboard │
              └─────────────────────────────┘
```

---

## 2. Tech Stack Selection

### 2.1 Lõi Agent — Ngôn ngữ hệ thống

| Thành phần | Ngôn ngữ đề xuất | Lý do |
|---|---|---|
| **Kernel Driver / Sensor** | **C++** (MSVC/WDK) | Windows Minifilter, WFP, ETW đều có SDK C++; hiệu năng tuyệt đối; tài liệu kernel phong phú |
| **User-space Agent Daemon** | **C++** (C++17/C++20) | Chạy native, không overhead; tích hợp mượt mà với Windows SDK và ONNX Runtime; dễ dàng debug trong Visual Studio |
| **Feature Extraction Engine** | **C++** | Đảm bảo hiệu năng tối đa cho các tính toán nặng (entropy, graph traversal); không tốn chi phí chuyển ngữ cảnh (context switch) |
| **ONNX Runtime Integration** | **C++** (Native API) | Sử dụng thư viện C++ gốc của Microsoft; không cần viết cgo bridge hay bindings trung gian; đạt độ trễ thấp nhất |
| **Response Handler** | **C++** | Gọi trực tiếp các Windows API hệ thống (TerminateProcess, WFP/Windows Firewall) thông qua headers tiêu chuẩn |

**Lý do chọn thuần C++ thay vì kết hợp Go**:
- Tích hợp ONNX Runtime C++ API native trực tiếp, tránh được sự phức tạp của cgo bridge.
- Chia sẻ trực tiếp các file header định nghĩa cấu trúc Telemetry Event giữa Kernel Driver và User-space Agent.
- Không có Garbage Collector (GC) overhead, kiểm soát dung lượng RAM ở mức cực thấp (< 15MB khi idle).
- Tích hợp Visual Studio và CMake giúp compile và debug đồng nhất một dự án.

**Lý do KHÔNG chọn Python cho Agent**:
- Python runtime quá nặng (~50MB), GIL giới hạn concurrency thực sự.
- Latency inference cao hơn nhiều khi gọi từ Python so với native C++.

### 2.2 AI/ML Stack — Huấn luyện & Triển khai

| Công đoạn | Công cụ | Vai trò |
|---|---|---|
| **Data Preparation** | Python + Pandas + NumPy | Làm sạch, transform telemetry dataset |
| **Feature Engineering (offline)** | Python + Scikit-learn Pipeline | Xây dựng transformer, scaler, encoder |
| **Model Training** | **LightGBM** (Multiclass: Benign / Malware / Credential) | Model chính — Supervised classification 3 lớp |
| **Model Training (Baseline)** | Random Forest (Scikit-learn) | Baseline so sánh độ chính xác |
| **Feature Config Export** | Python script (`export_features_config.py`) | Xuất `features_config.json` đi kèm `.onnx` để Agent load dynamic |
| **Model Export** | `skl2onnx`, `onnxmltools` | Chuyển model sang chuẩn `.onnx` |
| **Quantization** | ONNX Runtime Tools + `onnxruntime.quantization` | Giảm model size 4x, tăng tốc inference |
| **Runtime Inference** | **ONNX Runtime C++ API** (v1.17+) — Dynamic Input Shape | Tự động truy vấn shape `[1, N]` từ metadata `.onnx` session |
| **Experiment Tracking** | MLflow (local) | Theo dõi metric, version model |

### 2.3 Supporting Tools

```
Giám sát Telemetry:    Native ETW (Event Tracing for Windows) & Kernel Providers
Tấn công mô phỏng:    Atomic Red Team, CALDERA, PowerShell Empire
Sandbox:               VirtualBox / VMware Workstation (snapshot-based)
Phân tích dữ liệu:    ELK Stack (Elastic + Logstash + Kibana) — offline
Lưu trữ cục bộ:       SQLite 3 (WAL mode) + In-memory Ring Buffer
Build System:          CMake (C++), Visual Studio MSBuild
CI/CD:                 GitHub Actions (unit test + build check)
```

---

## 3. Môi trường Nền tảng & Triển khai

### 3.1 Cấu hình Sandbox Test

```
┌─────────────────────────────────────────────────────┐
│          HOST MACHINE (Development)                  │
│   Windows 10/11 Pro | RAM 16GB+ | SSD               │
│   Visual Studio 2022 + WDK 10 | Python 3.11          │
├─────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────┐   │
│  │     VM-1: Windows 10 (Victim/Test)            │   │
│  │     RAM: 4GB | Snapshot-based                 │   │
│  │     Windows OS with Admin privileges          │   │
│  │     EDR Agent deployed                        │   │
│  │     Network: Host-only adapter                │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────┐   │
│  │     VM-2: Kali Linux (Attacker — Optional)    │   │
│  │     RAM: 2GB | Metasploit, Sliver C2          │   │
│  │     Network: Host-only (same subnet as VM-1)  │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

**Bước cài đặt VM-1 (Windows Victim)**:
```powershell
# 1. Khởi tạo ETW Trace Session bằng logman (quyền Administrator) để ghi log dữ liệu hệ thống thô
logman create trace EDR_Telemetry_Session -ow -o C:\EDR\telemetry.etl
logman update trace EDR_Telemetry_Session -p "Microsoft-Windows-Kernel-Process" 0x10 4
logman update trace EDR_Telemetry_Session -p "Microsoft-Windows-Kernel-File" 0x10 4
logman update trace EDR_Telemetry_Session -p "Microsoft-Windows-Kernel-Registry" 0x10 4
logman update trace EDR_Telemetry_Session -p "Microsoft-Windows-Kernel-Network" 0x10 4
logman start EDR_Telemetry_Session

# 2. Cài Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# 3. Kiểm tra các phiên ETW đang chạy
logman query EDR_Telemetry_Session

# 4. Build & Deploy EDR Agent (unsigned driver — test mode)
bcdedit /set testsigning on
# Restart VM
sc create EDRDriver type=kernel start=demand binpath="C:\EDR\edr_driver.sys"
sc start EDRDriver
```

### 3.2 Triển khai Driver (Kernel Component)

```
Phương pháp tiếp cận (không cần EV cert trong môi trường test):
1. Enable Test Signing Mode: bcdedit /set testsigning on
2. Sử dụng WDK để build Minifilter driver (IRP hook cho File I/O)
3. ETW Provider: đăng ký provider GUID để nhận event từ kernel
4. Windows Filtering Platform (WFP): hook network traffic

Lưu ý kiến trúc:
- Driver (Ring-0) → chỉ thu thập & đẩy event vào kernel→user queue
- KHÔNG xử lý AI trong kernel (quá rủi ro BSoD)
- User-space agent đọc queue và thực hiện toàn bộ logic AI
```

### 3.3 Thu thập Dataset (Benign vs Malicious)

**Thu thập dữ liệu SẠCH (Benign)**:
```
1. Cài VM Windows fresh, cài office apps, browsers thông thường
2. Chạy các tác vụ thường ngày: mở Word, duyệt web, compile code
3. Thu thập 24-48h ETW logs (.etl) → dùng Python/C++ parser chuyển đổi sang định dạng JSON
4. Lọc bỏ noise: System/MsMpEng processes
```

**Thu thập dữ liệu ĐỘC HẠI (Malicious)**:
```
# Atomic Red Team — chạy các kỹ thuật MITRE ATT&CK
Invoke-AtomicTest T1059.001 -TestNumbers 1  # PowerShell encoded execution (ETW Kernel-Process: Event 1)
Invoke-AtomicTest T1003.001 -TestNumbers 1  # LSASS dump via Procdump (ETW Kernel-Process: Event 13/14 + Kernel-File: Event 64)
Invoke-AtomicTest T1003.001 -TestNumbers 2  # LSASS dump via comsvcs.dll MiniDump (ETW Kernel-Process: Event 13/14 + Kernel-File: Event 64)
Invoke-AtomicTest T1218.011 -TestNumbers 1  # Rundll32 DLL Sideloading (ETW Kernel-Process: Event 1 + Event 5)
Invoke-AtomicTest T1105 -TestNumbers 1      # Certutil download cradle (ETW Kernel-Process: Event 1 + Kernel-Network: Event 10 + Kernel-File: Event 64)
Invoke-AtomicTest T1547.001 -TestNumbers 1  # Registry Run Keys persistence (ETW Registry: Event 1/5)
Invoke-AtomicTest T1003.002 -TestNumbers 1  # SAM Registry credential dump (ETW Registry: Event 1/5 + Kernel-File: Event 64)
# NOTE: T1486 Ransomware đã loại khỏi scope. Thêm lại khi bật FileCollector mở rộng.

# Dataset công khai để huấn luyện thêm:
# - EMBER dataset (PE file features)
# - UNSW-NB15 (Network behavior)
# - DAPT 2020 (APT simulation logs)
# - CIC-IDS-2017 (Network intrusion)
```

---

## 4. Roadmap Phát triển

### Phase 0: Nền tảng (Tuần 1-2)
```
Goal: Setup môi trường, hiểu kiến trúc

[ ] Cài đặt và cấu hình VM Sandbox
[ ] Nghiên cứu ETW và Kernel Telemetry internals
[ ] Nghiên cứu MITRE ATT&CK framework
[ ] Hello-world ETW consumer bằng C++ sử dụng Windows SDK
[ ] Thu thập ETW log thô đầu tiên (.etl)
[ ] Đọc & phân tích cấu trúc event log XML/JSON

Deliverable: Môi trường sandbox hoạt động, có log mẫu và chương trình test ETW bằng C++
```

### Phase 1: Telemetry Collection (Tuần 3-5)
```
Goal: Agent thu thập được event từ OS

[ ] Implement Process Monitor (ETW: Microsoft-Windows-Kernel-Process)
[ ] Implement Registry Monitor (ETW: Microsoft-Windows-Kernel-Registry)
[ ] Normalize tất cả event về C++ struct chuẩn (xem telemetry_spec.md) và xuất JSON bằng nlohmann/json
[ ] Implement Ring Buffer in-memory (circular buffer, thread-safe queue sử dụng std::mutex và std::condition_variable)
[ ] Unit test: mỗi loại event được capture chính xác

Deliverable: Agent.exe bằng C++ thu thập và ghi event ra file JSON
```

### Phase 2: Feature Engineering (Tuần 6-8)
```
Goal: Biến raw event thành Feature Vector cho AI

[ ] Implement Process Lineage Graph (Adjacency List, in-memory)
[ ] Implement Sliding Window aggregation (5s, 30s, 300s)
[ ] Implement Behavioral Sequence encoder (process chain → vector)
[ ] Implement Feature Normalizer (Min-Max / Z-score)
[ ] Thiết kế IFeatureExtractor interface và FeatureRegistry class
[ ] Implement features_config.json schema và dynamic reader trong C++ Agent
[ ] Implement Default Value Imputation (0.0 cho binary/count, -1.0 cho float/score khi collector tắt)
[ ] Offline: xây dựng feature pipeline Python (sklearn Pipeline)
[ ] Thu thập dataset Benign + Malicious đủ lớn (~10K events mỗi class)
[ ] EDA (Exploratory Data Analysis) trên dataset

Deliverable: Feature vector pipeline hoạt động end-to-end
```

### Phase 3: AI Model Training & Export (Tuần 9-11)
```
Goal: Huấn luyện và export model sang .onnx

[ ] Train LightGBM Multiclass (3 classes: 0=Benign, 1=Malware Behavior, 2=Credential Access)
[ ] Train Random Forest Classifier (baseline so sánh)
[ ] Đánh giá: Precision, Recall, F1, AUC-ROC per class
[ ] Tối ưu hyperparameter (Optuna)
[ ] Export model sang .onnx (skl2onnx / onnxmltools)
[ ] Export features_config.json đi kèm .onnx (thứ tự + tên đặc trưng khớp đầu vào mô hình)
[ ] Quantize model sang INT8 (onnxruntime.quantization)
[ ] Validate: output ONNX == output Python (tolerance < 1e-5)

Deliverable: edr_model.onnx (< 5MB), Accuracy > 90%
```

### Phase 4: Agent Integration (Tuần 12-14)
```
Goal: Tích hợp ONNX model vào C++ Agent

[ ] Tích hợp trực tiếp ONNX Runtime C++ API vào C++ agent
[ ] Implement Dynamic ONNX Shape query (đọc input shape [1, N] từ .onnx session metadata)
[ ] Implement Dynamic Collector Registration từ agent_config.json
[ ] Implement Tiered Inference (Rule → ML → Graph)
[ ] Implement Threat Scoring (0.0 → 1.0)
[ ] Implement Response Engine (Alert, Kill, Report)
[ ] Load response_policy.json (cấu hình ngưỡng hành động sử dụng nlohmann/json)
[ ] Integration test: inject mock malicious event → agent alert đúng

Deliverable: Agent hoàn chỉnh viết bằng C++ với AI inference realtime
```

### Phase 5: Evaluation & Optimization (Tuần 15-16)
```
Goal: Đánh giá hiệu năng và giảm False Positive

[ ] Benchmark CPU/RAM usage (target: CPU < 5%, RAM < 100MB)
[ ] Đo inference latency (target: < 50ms/event)
[ ] Chạy Atomic Red Team toàn bộ → đo Detection Rate
[ ] Phân tích False Positive với workload thường ngày
[ ] Điều chỉnh threshold trong response_policy.json
[ ] Tài liệu hóa kết quả benchmark

Deliverable: Báo cáo đánh giá, demo video, technical report
```

---

## 5. Cấu trúc Thư mục Dự án

```
EDR_AI_Agent/
├── docs/                          # Tài liệu kỹ thuật
│   ├── planning.md                # File này
│   ├── agent.md                   # Đặc tả agent
│   ├── telemetry_spec.md          # Struct định nghĩa event
│   ├── feature_engineering.md     # Thuật toán feature
│   ├── model_pipeline.md          # ML pipeline
│   └── benchmark_spec.md          # Tiêu chí đánh giá
│
├── agent/                         # C++ agent (user-space)
│   ├── src/
│   │   ├── main.cpp
│   │   ├── collector/             # ETW consumers
│   │   │   └── collector.cpp      # Unified ETW consumer
│   │   ├── pipeline/              # Event normalization & buffering
│   │   │   └── normalizer.cpp
│   │   ├── features/              # Feature extraction (Stubs)
│   │   │   ├── lineage_graph.cpp
│   │   │   ├── sliding_window.cpp
│   │   │   └── entropy.cpp
│   │   ├── inference/             # AI inference (Stubs)
│   │   │   ├── onnx_inferencer.cpp
│   │   │   ├── rule_engine.cpp
│   │   │   └── scorer.cpp
│   │   └── response/              # Response actions (Stubs)
│   │       ├── alert.cpp
│   │       ├── kill_process.cpp
│   │       └── block_network.cpp
│   ├── include/                   # Header files
│   │   ├── telemetry/             # Standardized events schemas
│   │   │   ├── base.h
│   │   │   ├── process.h
│   │   │   ├── file.h
│   │   │   ├── network.h
│   │   │   ├── dns.h
│   │   │   ├── registry.h
│   │   │   ├── process_access.h
│   │   │   └── alert.h
│   │   ├── collector.h
│   │   ├── collector_registry.h
│   │   ├── normalized_event.h
│   │   ├── normalizer.h
│   │   ├── ringbuffer.h
│   │   ├── features.h
│   │   ├── inference.h
│   │   ├── response.h
│   │   └── common.h               # Shared telemetry structs
│   ├── configs/
│   │   ├── agent_config.json        # Bật/tắt từng collector module (process, file, network, registry, dll)
│   │   ├── features_config.json     # Danh sách + thứ tự đặc trưng cho mô hình ONNX hiện tại
│   │   └── response_policy.json
│   ├── third_party/               # nlohmann/json header
│   └── CMakeLists.txt
│
├── driver/                        # C++ Kernel driver (optional)
│   ├── edr_minifilter/
│   │   ├── edr_minifilter.c
│   │   ├── edr_minifilter.h
│   │   └── CMakeLists.txt
│   └── etw_provider/
│       └── etw_provider.cpp
│
├── ml/                            # Python ML pipeline
│   ├── data/
│   │   ├── raw/                   # ETW logs raw (.etl)
│   │   ├── processed/             # Feature vectors CSV
│   │   └── models/                # Trained models + .onnx
│       │                      # (features_config.json được auto-export cùng .onnx sau training)
│   ├── notebooks/
│   │   ├── 01_eda.ipynb
│   │   ├── 02_feature_engineering.ipynb
│   │   ├── 03_training.ipynb
│   │   └── 04_export_onnx.ipynb
│   ├── src/
│   │   ├── feature_pipeline.py
│   │   ├── train.py
│   │   ├── export_onnx.py
│   │   └── quantize.py
│   └── requirements.txt
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── atomic_red_team/           # Test scripts
│
└── index.txt                      # Project specification
```

---

## 6. Ngưỡng Hiệu năng Bắt buộc

| Chỉ số | Mục tiêu | Phương pháp đo |
|---|---|---|
| CPU Usage (agent) | < 5% trung bình | Windows Performance Monitor |
| RAM Usage | < 100 MB | Working Set via Task Manager |
| Inference Latency | < 50ms / event | C++ std::chrono benchmark |
| Detection Rate | > 85% (trên Atomic Red Team set) | TP / (TP + FN) |
| False Positive Rate | < 5% | FP / (FP + TN) trên benign workload |
| Model Size (.onnx) | < 5 MB | File size sau quantization |
| Event Throughput | > 1000 events/s | Ring buffer benchmark |

---

## 7. Rủi ro & Biện pháp Giảm thiểu

| Rủi ro | Mức độ | Biện pháp |
|---|---|---|
| Driver BSoD trong test | Cao | Luôn dùng VM + snapshot; KHÔNG test driver trực tiếp trên host |
| Model overfitting do dataset nhỏ | Trung bình | Data augmentation; sử dụng dataset công khai; cross-validation |
| False Positive cao → alert fatigue | Cao | Whitelist hệ thống; threshold tuning; behavioral context |
| ONNX Runtime version conflict | Thấp | Pin version trong CMakeLists; test trên CI |
| ETW session config capture thiếu event | Thấp | Cấu hình đúng Keyword và Provider GUID; test từng event type |
| Ethical/Legal khi test malware | Cao | CHỈ dùng Atomic Red Team simulation; KHÔNG dùng live malware; test trong VM isolated |

---

## 8. Tài nguyên Học tập

```
Sách & Whitepaper:
- "The Art of Memory Forensics" — Ligh, Case, Levy, Richard
- "Windows Internals" (Part 1 & 2) — Russinovich, Solomon
- "Practical Malware Analysis" — Sikorski, Honig
- CrowdStrike Intelligence Reports (APT behavior analysis)

Online Resources:
- MITRE ATT&CK: https://attack.mitre.org/
- Sysinternals Suite: https://docs.microsoft.com/en-us/sysinternals/
- ETW Documentation: https://docs.microsoft.com/en-us/windows/win32/etw/
- ONNX Runtime: https://onnxruntime.ai/docs/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team

Dataset công khai:
- EMBER: https://github.com/elastic/ember
- UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- CIC Datasets: https://www.unb.ca/cic/datasets/
```
