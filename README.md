# EDR AI Agent (Detect Malware Behavior)

> **Endpoint Detection & Response** — AI/ML Engine tích hợp trực tiếp trên Endpoint  
> **Ngôn ngữ:** C++17 + Python 3.11  
> **Nền tảng:** Windows 10/11 

---

## Mục lục

- [Kiến trúc hệ thống](#-kiến-trúc-hệ-thống)
- [Những gì đã làm được](#-những-gì-đã-làm-được)
- [Cấu trúc thư mục](#-cấu-trúc-thư-mục)
- [Tech Stack](#-tech-stack)
- [Hướng dẫn Build & Chạy](#-hướng-dẫn-build--chạy)
- [ML Pipeline](#-ml-pipeline)
- [Mô phỏng tấn công](#-mô-phỏng-tấn-công)
- [Cấu hình](#-cấu-hình)

---



## Kiến trúc hệ thống

```
┌──────────────────────────────────────────────────────────────────┐
│                    ENDPOINT (Windows 10/11)                       │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │               EDR SENSOR LAYER (ETW / WMI)                  │  │
│  │                     Process Monitor
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                      │
│                             ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                    TELEMETRY PIPELINE                        │  │
│  │   Event Normalizer → JSON Struct → In-memory Ring Buffer     │  │
│  │   Persistent Storage: SQLite 3 (WAL mode)                    │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                      │
│                             ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │              FEATURE EXTRACTION ENGINE                       │  │
│  │   Process Lineage Graph │ Sliding Window │ Entropy Calc      │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                      │
│                             ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │             TIERED AI INFERENCE ENGINE                       │  │
│  │   Tier-1: Rule / Whitelist Filter  (agent_config.json)       │  │
│  │   Tier-2: LightGBM Multiclass Model (ONNX, Dynamic Shape)   │  │
│  │   Tier-3: Behavioral Graph Correlation                       │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                      │
│                             ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                   RESPONSE ENGINE                            │  │
│  │                  Alert  │  Kill Process                      │  │
│  └─────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---


### 1. Telemetry Collector (`agent/src/collector/`)

- **Thu thập sự kiện Windows** qua WMI (Windows Management Instrumentation):
  - `PROCESS_CREATE` / `PROCESS_EXIT` — giám sát vòng đời tiến trình

- Mỗi event được gắn timestamp UTC (ISO 8601), process ID, process name, command line

### 2. Telemetry Normalizer (`agent/src/pipeline/`)

- Chuẩn hóa raw event thành `NormalizedEvent` struct thống nhất
- Mapping event type string → enum nội bộ
- Trích xuất fields: `pid`, `ppid`, `process_name`, `cmdline`, `file_path`, `dst_ip`, `dst_port`, `reg_key`...
- Serialization sang JSON theo `telemetry_spec.md`
- Ghi event ra **SQLite 3** (WAL mode) — bảng `telemetry_events`

### 3. In-memory Ring Buffer (`agent/include/ringbuffer.h`)

- Lock-free circular buffer tốc độ cao cho pipeline event
- Kích thước cấu hình được, tránh memory leak khi agent chạy liên tục

### 4. Process Lineage Graph (`agent/src/features/lineage_graph.cpp`)

- Xây dựng cây quan hệ cha-con giữa các tiến trình (PID → PPID)
- Tính **độ sâu chuỗi tiến trình** (chain depth) để phát hiện process injection
- Phát hiện **command-line injection patterns**: `powershell -enc`, `cmd /c`, `wscript`...
- Cung cấp feature: `process_chain_depth`

### 5. Sliding Window Feature Extractor (`agent/src/features/sliding_window.cpp`)

- Cửa sổ thời gian động (configurable, mặc định 60 giây) theo từng PID
- Đếm tần suất event: `file_ops_per_minute`, `net_conns_per_minute`, `reg_writes_per_minute`
- Phát hiện **burst behavior** — đặc trưng của ransomware và data exfiltration

### 6. Entropy Calculator (`agent/src/features/entropy.cpp`)

- Tính **Shannon entropy** của tên file và đường dẫn
- Phát hiện tên file/process ngẫu nhiên — dấu hiệu của malware dropper
- Feature: `cmd_entropy`, `path_entropy`

### 7. ONNX Inference Engine (`agent/include/onnx_inferencer.h`)

- Tích hợp **ONNX Runtime C++ API** (v1.17+)
- Load model `.onnx` tại runtime từ `agent_config.json`
- Hỗ trợ **Dynamic Input Shape** — tự động query số feature từ metadata session
- Load **scaler params** (`scaler_params.json`) để chuẩn hóa input trước khi inference
- Output: xác suất 2 lớp — `Benign`, `Malware`

### 8. Rule Engine (`agent/include/rule_engine.h`)

- **Tier-1 fast-path** trước khi gọi ONNX model
- Load rules từ `response_policy.json`
- Phát hiện nhanh: Mimikatz, PowerShell Empire, encoded commands
- Hỗ trợ: `contains`, `regex`, `greater_than`, `less_than`, `equals` operators
- Tránh false positive bằng whitelist process name

### 9. Scorer — Hybrid Scoring (`agent/include/scorer.h`)

- Kết hợp điểm từ Rule Engine (Tier-1) + ONNX Model (Tier-2)
- Công thức: `final_score = rule_weight * rule_score + ml_weight * ml_score`
- Ngưỡng cấu hình: `alert_threshold`, `kill_threshold`, `block_threshold`

### 10. Response Engine (`agent/src/response/`)

- **`alert.cpp`** — Ghi alert
- **`kill_process.cpp`** — Gọi `TerminateProcess()` Windows API để kill process độc hại
- **`block_network.cpp`** — Stub cho Windows Firewall / WFP rule injection

### 11. Main Agent Loop (`agent/src/main.cpp`)

- Multi-threaded pipeline: Collector thread → Normalizer → Feature Extractor → Scorer → Response
- Graceful shutdown bằng `Ctrl+C` (signal handler)
- Load toàn bộ config từ `agent_config.json` khi khởi động
- Fallback: khi ONNX model không load được → chỉ dùng Rule Engine
- Output: event JSON log + alert log ra SQLite + console

---

### 12. ML Pipeline (`ml/`)

#### Dataset & Feature Engineering

- **Raw data** tổng hợp từ mô phỏng Atomic Red Team + benign workload
- **EDA (Exploratory Data Analysis)** — `ml/eda_features.ipynb` + `ml/src/run_eda.py`
- **Feature set gồm 34+ đặc trưng**:
  - Behavioral: `file_ops`, `net_conns`, `reg_writes`, `process_chain_depth`
  - Entropy: `cmd_entropy`, `path_entropy`
  - Boolean flags: `has_encoded_cmd`, `parent_is_office`, `uses_lolbin`
  - Network: `dst_port`, `bytes_sent`, `conn_frequency`

#### Model Training — v1 (`ml/src/train.py`)

- **LightGBM** multiclass (3 lớp: Benign / Malware / CredentialAccess)
- Hyperparameter tuning với **Optuna** (100 trials)
- **Random Forest** baseline để so sánh
- Cross-validation 5-fold, metric: F1-score macro
- Kết quả lưu: `ml/data/models/best_lgb_model.pkl` + `best_lgb_model.txt`

#### Model Training — v2 (`ml/src/train_v2.py`)

- Data augmentation cho class `CredentialAccess` (`augment_credential.py`)
- Cải thiện class imbalance handling (SMOTE-like augmentation)
- Feature metadata xuất ra `feature_meta_v2.json`
- Kết quả lưu: `ml/data/models_v2/`

#### ONNX Export & Quantization

- **v1**: `export_onnx.py` → `edr_model.onnx` (~391KB) | `quantize.py` → `edr_model_int8.onnx`
- **v2**: `export_onnx_v2.py` → `edr_model_v2.onnx` (~369KB) | `quantize_v2.py` → `edr_model_v2_int8.onnx`
- Validation ONNX output: `validate_onnx.py` / `validate_onnx_v2.py`

---

### 13. 🔴 Attack Simulation Scripts (`simulate*.ps1`)

- **`simulate.ps1`** — Mô phỏng cơ bản: PowerShell encoded command, registry persistence
- **`simulate1.ps1`** — Mô phỏng Mimikatz credential dump (LSASS access)
- **`simulate3.ps1`** — Mô phỏng ransomware file encryption burst
- **`simulate4.ps1`** — Mô phỏng C2 beaconing + lateral movement

### 14. Documentation (`docs/`)

| File | Nội dung |
|------|----------|
| `planning.md` | Kế hoạch tổng thể, kiến trúc, tech stack |
| `telemetry_spec.md` | Đặc tả cấu trúc event telemetry |
| `feature_engineering.md` | Mô tả 34+ features và logic trích xuất |
| `model_pipeline.md` | Pipeline huấn luyện, export, quantize model |
| `agent.md` | Chi tiết triển khai C++ agent |
| `benchmark_spec.md` | Đặc tả benchmark và KPI hiệu năng |

---

## Cấu trúc thư mục

```
EDR_AI_Agent/
├── agent/                          # C++ Agent (core engine)
│   ├── CMakeLists.txt
│   ├── configs/
│   │   ├── agent_config.json       # Cấu hình chính (thresholds, paths)
│   │   ├── features_config.json    # Feature schema cho ONNX input
│   │   ├── response_policy.json    # Rules cho Rule Engine
│   │   └── scaler_params.json      # Mean/std để normalize features
│   ├── include/                    # Header files
│   │   ├── collector.h
│   │   ├── collector_registry.h
│   │   ├── common.h
│   │   ├── entropy.h
│   │   ├── features.h              # Feature struct (34+ fields)
│   │   ├── lineage_graph.h
│   │   ├── normalized_event.h
│   │   ├── normalizer.h
│   │   ├── onnx_inferencer.h
│   │   ├── response.h
│   │   ├── ringbuffer.h
│   │   ├── rule_engine.h
│   │   ├── scorer.h
│   │   └── sliding_window.h
│   ├── src/
│   │   ├── main.cpp                # Entry point + agent loop
│   │   ├── collector/
│   │   │   └── collector.cpp       # WMI/ETW event collection
│   │   ├── features/
│   │   │   ├── entropy.cpp
│   │   │   ├── lineage_graph.cpp
│   │   │   └── sliding_window.cpp
│   │   ├── inference/              # ONNX + Rule Engine stubs
│   │   ├── pipeline/
│   │   │   └── normalizer.cpp      # Event normalization
│   │   └── response/
│   │       ├── alert.cpp
│   │       ├── block_network.cpp
│   │       └── kill_process.cpp
│   └── third_party/
│       ├── nlohmann/               # JSON library (header-only)
│       ├── onnxruntime/            # ONNX Runtime C++ SDK
│       └── sqlite/                 # SQLite3 amalgamation
├── ml/                             # Python ML Pipeline
│   ├── requirements.txt
│   ├── eda_features.ipynb          # Jupyter EDA notebook
│   ├── data/
│   │   ├── raw/                    # Raw telemetry dataset
│   │   ├── eda/                    # EDA outputs
│   │   ├── models/                 # v1 trained models
│   │   │   ├── best_lgb_model.pkl
│   │   │   ├── edr_model.onnx      (~391 KB)
│   │   │   └── edr_model_int8.onnx (INT8 quantized)
│   │   └── models_v2/             # v2 trained models
│   │       ├── best_lgb_model_v2.pkl
│   │       ├── edr_model_v2.onnx   (~369 KB)
│   │       ├── edr_model_v2_int8.onnx
│   │       └── feature_meta_v2.json
│   └── src/
│       ├── run_eda.py
│       ├── train.py                # v1 training pipeline
│       ├── train_v2.py             # v2 training 
│       ├── augment_credential.py   # Credential class augmentation
│       ├── export_onnx.py          # v1 ONNX export
│       ├── export_onnx_v2.py       # v2 ONNX export
│       ├── quantize.py             # v1 INT8 quantization
│       ├── quantize_v2.py          # v2 INT8 quantization
│       ├── validate_onnx.py        # v1 ONNX validation
│       └── validate_onnx_v2.py     # v2 ONNX validation
├── docs/                           # Technical documentation
│   ├── planning.md
│   ├── telemetry_spec.md
│   ├── feature_engineering.md
│   ├── model_pipeline.md
│   ├── agent.md
│   └── benchmark_spec.md
├── simulate.ps1                    # Attack simulation scripts
├── simulate1.ps1
├── simulate3.ps1
├── simulate4.ps1
├── atomic_tests_guide.md           # Hướng dẫn Atomic Red Team tests
├── response_policy.json            # Global response policy
├── CMakeLists.txt                  # Root CMake
└── README.md
```

---

## 🛠️ Tech Stack

| Thành phần | Công nghệ |
|---|---|
| **Agent Core** | C++17 (MSVC / Visual Studio 2022) |
| **Build System** | CMake 3.20+ |
| **Telemetry Collection** | Windows WMI / ETW |
| **ML Runtime** | ONNX Runtime C++ API v1.17+ |
| **ML Training** | Python 3.11, LightGBM, Scikit-learn, Optuna |
| **Model Format** | ONNX (FP32) + INT8 Quantized |
| **JSON** | nlohmann/json (header-only) |
| **Database** | SQLite 3 (WAL mode, amalgamation) |
| **Hyperparameter Tuning** | Optuna (Bayesian optimization) |

---

## Hướng dẫn Build & Chạy

> **Yêu cầu chạy CMD/PowerShell với quyền Administrator**

### Prerequisites

- Visual Studio 2022 (với C++ workload)
- CMake 3.20+
- Python 3.11 (cho ML pipeline)

### Build

```powershell
# Cấu hình và build dự án bằng CMake
cmake -B build -S .
cmake --build build --config Release
```

### Run

```powershell
# Di chuyển tới thư mục chứa file thực thi
cd D:\Universe\VCS\EDR_AI_Agent\build\agent\Release

# Khởi chạy agent với file cấu hình
.\edr_agent.exe D:\Universe\VCS\EDR_AI_Agent\agent\configs\agent_config.json
```

---

## ML Pipeline

### Cài đặt Python dependencies

```powershell
cd ml
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### Huấn luyện model

```powershell
# Chạy EDA
python src/run_eda.py

# Train v2
python src/train_v2.py

# Export ONNX
python src/export_onnx_v2.py

# Quantize INT8
python src/quantize_v2.py

# Validate
python src/validate_onnx_v2.py
```

---

> **Chỉ chạy trong môi trường sandbox/VM có snapshot. Không chạy trên máy thật.**


## Cấu hình

### `agent/configs/agent_config.json`

Cấu hình chính của agent:
- Đường dẫn ONNX model
- Ngưỡng điểm: `alert_threshold`, `kill_threshold`
- Kích thước ring buffer
- Sliding window size (giây)

### `agent/configs/response_policy.json`

Các rule phát hiện nhanh (Tier-1):
- rules bao gồm: Mimikatz, PowerShell Empire, encoded commands
- Hỗ trợ operators: `contains`, `regex`, `greater_than`, `equals`

### `response_policy.json` (root)

Global response policy với action mapping theo mức độ threat score.

---

## 📊 Trạng thái phát triển

| Module | Trạng thái |
|--------|-----------|
| Telemetry Collector (WMI) | ✅ Hoàn thành |
| Event Normalizer | ✅ Hoàn thành |
| Ring Buffer | ✅ Hoàn thành |
| Process Lineage Graph | ✅ Hoàn thành |
| Sliding Window Features | ✅ Hoàn thành |
| Entropy Calculator | ✅ Hoàn thành |
| Rule Engine (Tier-1) | ✅ Hoàn thành |
| ONNX Inferencer (Tier-2) | ✅ Hoàn thành |
| Hybrid Scorer | ✅ Hoàn thành |
| Response: Alert | ✅ Hoàn thành |
| Response: Kill Process | ✅ Hoàn thành |
| Response: Block Network | (chưa hoàn thiện) |
| ML Training v1 | ✅ Hoàn thành |
| ML Training v2 (augmented) | ✅ Hoàn thành |
| ONNX Export & Quantize | ✅ Hoàn thành |


---


