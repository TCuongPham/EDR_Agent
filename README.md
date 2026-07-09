# EDR AI Agent: Phát hiện Hành vi Mã độc trên Endpoint

## Kiến trúc Hệ thống

```
┌────────────────────────────────────────────────────────────────────────┐
│                        WINDOWS ENDPOINT (User Space)                   │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    EDR SENSOR LAYER (ETW)                        │  │
│  │  Microsoft-Windows-Kernel-Process -> Bắt sự kiện tạo/thoát proc   │  │
│  └─────────────────────────────────┬────────────────────────────────┘  │
│                                    │ Raw Event [PID, PPID, Path, Cmd]  │
│                                    ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   TIỀN XỬ LÝ TELEMETRY                           │  │
│  │  • Normalizer: Làm giàu ngữ cảnh, fallback truy vấn CommandLine PEB│  │
│  │  • Ring Buffer: Hàng đợi đệm vòng 64K slots không khóa (tránh bão)│  │
│  │  • SQLite 3: Lưu trữ (telemetry_events) │  │
│  └─────────────────────────────────┬────────────────────────────────┘  │
│                                    │ NormalizedEvent                   │
│                                    ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   BỘ TRÍCH XUẤT ĐẶC TRƯNG                        │  │
│  │  • Đồ thị phả hệ tiến trình  • Cửa sổ trượt (30s) • Shannon Entropy│  │
│  │  • Đầu ra: Vector đặc trưng hành vi 16 chiều đã được chuẩn hóa    │  │
│  └─────────────────────────────────┬────────────────────────────────┘  │
│                                    │ Feature Vector [x0..x15]          │
│                                    ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                  BỘ SUY DIỄN AI/ML PHÂN CẤP                      │  │
│  │                                                                  │  │
│  │  Tier-1: Rule Engine lọc nhanh (Whitelist + Luật Regex)          │  │
│  │  Tier-2: Suy diễn ONNX (Mô hình LightGBM)                         │  │
│  │           ↳ Tính toán xác suất mã độc P(Malware) trong [0.0, 1.0] │  │
│  │  Tier-3: Đồ thị tương quan hành vi (Behavior Graph Correlation)  │  │
│  │           ↳ Duyệt ngược phả hệ phát hiện chuỗi Office -> Shell    │  │
│  └─────────────────────────────────┬────────────────────────────────┘  │
│                                    │ ScoringContext + Điểm cuối cùng   │
│                                    ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                        TẦNG PHẢN ỨNG CỤC BỘ                      │  │
│  │  • Alert  -> In console thời gian thực + Ghi log cấu trúc JSONL   │  │
│  │  • Kill   -> Gọi Win32 API TerminateProcess()                     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Tập Đặc trưng 

Tác nhân trích xuất một **vector đặc trưng 16 chiều** cho mỗi sự kiện tiến trình. Tất cả các đặc trưng được chuẩn hóa về đoạn $[0.0, 1.0]$ bằng cách áp dụng log-scaling và min-max dựa trên các tham số từ tệp `scaler_params.json`.

| STT | Tên đặc trưng | Kiểu dữ liệu | Mô tả ý nghĩa hành vi |
|---|---|---|---|
| 0 | `child_spawn_count_30s` | Count | Số lượng tiến trình con được tạo ra trong cửa sổ trượt 30 giây. |
| 1 | `cmdline_length` | Integer | Độ dài ký tự của chuỗi dòng lệnh tiến trình. |
| 2 | `cmdline_entropy` | Float | Độ hỗn loạn thông tin Shannon Entropy của dòng lệnh. |
| 3 | `has_encoded_cmdline` | Boolean | Dòng lệnh chứa cờ chạy mã hóa Base64 (ví dụ: `-enc`, `-encoded`, `/enc`). |
| 4 | `has_download_cradle` | Boolean | Dòng lệnh chứa chuỗi tải payload (ví dụ: `iwr`, `Invoke-WebRequest`, `curl`). |
| 5 | `cmdline_suspicious_kw_count` | Count | Tần suất xuất hiện từ khóa nghi ngờ (ví dụ: `bypass`, `lsass`, `vssadmin`, `shadowcopy`). |
| 6 | `is_lolbin` | Boolean | Tệp thực thi là công cụ hệ thống LOLBin (ví dụ: `powershell.exe`, `certutil.exe`). |
| 7 | `parent_is_lolbin` | Boolean | Tiến trình cha là một công cụ hệ thống LOLBin. |
| 8 | `token_elevated` | Boolean | Tiến trình chạy với quyền quản trị nâng cao hoặc quyền hệ thống (SYSTEM). |
| 9 | `process_depth_in_tree` | Integer | Độ sâu của tiến trình hiện tại trong cây phả hệ lưu trong RAM. |
| 10 | `parent_is_script_engine` | Boolean | Tiến trình cha là bộ dịch kịch bản (`powershell.exe`, `cmd.exe`, `wscript.exe`). |
| 11 | `is_in_temp_path` | Boolean | Tệp thực thi chạy từ thư mục tạm của hệ thống (ví dụ: `AppData\Local\Temp`). |
| 12 | `is_in_system_path` | Boolean | Tệp thực thi chạy từ thư mục hệ thống (ví dụ: `System32`, `SysWOW64`). |
| 13 | `lifetime_ms_log` | Float | Logarit thời gian tồn tại của tiến trình (chỉ tính khi tiến trình kết thúc). |
| 14 | `unusual_parent_child` | Float | Điểm rủi ro mối quan hệ cha-con bất thường (ví dụ: Office sinh shell). |
| 15 | `tree_fan_out_max` | Integer | Số lượng con trực tiếp lớn nhất được sinh ra bởi một nút bất kỳ trong cây con. |


---

## Cấu trúc Thư mục

```
EDR_AI_Agent/
├── agent/                          # Mã nguồn C++ Agent
│   ├── CMakeLists.txt              # Cấu hình biên dịch CMake
│   ├── configs/                    # Các file cấu hình hệ thống
│   │   ├── agent_config.json       # Ngưỡng điểm và đường dẫn mô hình
│   │   ├── features_config.json    # Lược đồ các đặc trưng kích hoạt
│   │   ├── response_policy.json    # Chính sách phản ứng (Alert/Kill)
│   │   └── scaler_params.json      # Biên giá trị min/max để chuẩn hóa
│   ├── include/                    # Định nghĩa các file Header
│   │   ├── collector.h             # Giao tiếp thu thập ETW
│   │   ├── features.h              # Logic trích xuất 16 đặc trưng
│   │   ├── lineage_graph.h         # Quản lý cây tiến trình trong bộ nhớ
│   │   ├── normalized_event.h      # Cấu trúc sự kiện chuẩn hóa
│   │   ├── normalizer.h            # Làm giàu thông tin & cache tiến trình
│   │   ├── onnx_inferencer.h       # Thư viện suy diễn ONNX Runtime C++
│   │   ├── response.h              # Xử lý Alert & TerminateProcess
│   │   ├── ringbuffer.h            # Hàng đợi đệm vòng đồng bộ đa luồng
│   │   ├── rule_engine.h           # Bộ lọc nhanh Tier-1
│   │   └── scorer.h                # Thuật toán chấm điểm hỗn hợp 3 tầng
│   ├── src/                        # Triển khai mã nguồn chi tiết
│   │   ├── main.cpp                # Luồng chạy chính EDR Daemon
│   │   ├── collector/              # Hiện thực thu thập sự kiện WMI/ETW
│   │   ├── features/               # Tính entropy, lineage graph, sliding window
│   │   ├── pipeline/               # Chuẩn hóa sự kiện
│   │   └── response/               # Gọi API TerminateProcess & in log alert
│   └── third_party/                # Thư viện nhúng (SQLite3, JSON header)
├── ml/                             # Python Machine Learning Pipeline
│   ├── requirements.txt            # Thư viện Python cần thiết
│   ├── eda_features.ipynb          # Notebook phân tích dữ liệu EDA
│   ├── data/
│   │   └── models_v2/              # Các mô hình (LightGBM & ONNX)
│   │       ├── best_lgb_model_v2.pkl
│   │       ├── edr_model_v2.onnx   # Mô hình ONNX FP32 (~332 KB)
│   │       ├── edr_model_v2_int8.onnx # Mô hình ONNX lượng tử hóa INT8 (~111 KB)
│   │       └── feature_meta_v2.json # Metadata thứ tự 16 đặc trưng
│   └── src/                        # Mã nguồn pipeline ML
│       ├── train_v2.py             # Huấn luyện & tối ưu hóa siêu tham số (Optuna)
│       ├── export_onnx_v2.py       # Xuất mô hình sang chuẩn ONNX
│       ├── quantize_v2.py          # Lượng tử hóa mô hình sang INT8
│       └── validate_onnx_v2.py     # Kiểm tra độ chính xác mô hình ONNX
└── simulate.ps1                    # Script mô phỏng hành vi mã độc
```

---

## Biên dịch & Chạy

### Yêu cầu hệ thống
*   **Hệ điều hành**: Windows 10 hoặc Windows 11 (64-bit).
*   **Bộ biên dịch**: Visual Studio 2022 (đã cài đặt gói phát triển C++ Desktop).
*   **Công cụ build**: CMake (phiên bản v3.20 hoặc mới hơn).
*   **Thư viện**: SDK ONNX Runtime C++ (được tự động định cấu hình).

### Biên dịch C++ Agent
Khởi chạy Command Prompt hoặc PowerShell với quyền **Administrator** và thực thi:

```powershell
# 1. Cấu hình và tạo file project Visual Studio bằng CMake
cmake -B build -S .

# 2. Tiến hành biên dịch dự án ở chế độ Release
cmake --build build --config Release
```

### Chạy EDR Agent
Di chuyển tới thư mục chứa tệp thực thi vừa được biên dịch và chạy kèm đường dẫn file cấu hình:

```powershell
# Di chuyển tới thư mục output
cd build/agent/Release

# Chạy Agent với quyền Administrator
./edr_agent.exe Z:/EDR_AI_Agent/agent/configs/agent_config.json
```

---

## ML Pipeline & Huấn luyện (Python)

Để huấn luyện lại hoặc tối ưu hóa mô hình LightGBM trong thư mục `ml/`:

1.  **Cài đặt thư viện**:
    ```bash
    pip install -r requirements.txt
    ```
2.  **Huấn luyện mô hình tối ưu**:
    Chạy tập lệnh huấn luyện LightGBM và tự động tối ưu hóa siêu tham số bằng **Optuna** (100 trials) để tối đa hóa điểm F1-score:
    ```bash
    python src/train_v2.py
    ```
3.  **Xuất sang định dạng ONNX**:
    Chuyển đổi mô hình đã huấn luyện sang định dạng ONNX:
    ```bash
    python src/export_onnx_v2.py
    ```
4.  **Lượng tử hóa mô hình**:
    Chuyển đổi mô hình `.onnx` sang định dạng 8-bit quantized (`_int8.onnx`):
    ```bash
    python src/quantize_v2.py
    ```

---

## Mô phỏng Tấn công & Kiểm thử

Khả năng phát hiện và ngăn chặn của Agent được kiểm chứng thông qua tệp kịch bản mô phỏng tích hợp `simulate.ps1`.

Chạy tập lệnh trong PowerShell (Bypass execution policy) dưới quyền **Administrator**:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\simulate.ps1
```

Tệp lệnh sẽ giả lập 7 hành vi tấn công tương ứng với các kỹ thuật trong ma trận MITRE ATT&CK:
1.  **Registry Run Key Persistence** (T1547.001): Tạo khóa đăng ký khởi động trong HKCU.
2.  **Download Cradle** (T1105 / T1059.001): Khởi tạo tiến trình PowerShell ẩn để tải payload bằng lệnh `Invoke-WebRequest`.
3.  **Obfuscated Command Execution** (T1027 / T1059.001): Chạy PowerShell ẩn với tham số dòng lệnh Base64 (`-enc`).
4.  **Temp Path Execution** (T1036 / T1074): Sao chép công cụ hệ thống và thực thi trực tiếp từ thư mục tạm `Temp`.
5.  **Scheduled Task Creation** (T1053.005): Tạo tác vụ lập lịch hàng ngày thông qua công cụ `schtasks.exe`.
6.  **Windows Service Creation** (T1543.003): Tạo và đăng ký một Windows Service độc hại bằng `sc.exe`.
7.  **Recovery Inhibition** (T1486): Chạy lệnh cmd gọi `vssadmin` hoặc `shadowcopy` nhằm xóa các bản sao lưu khôi phục của hệ thống.

### Kết quả Phản ứng Kỳ vọng
Đối với mỗi hành vi được thực thi:
*   Bộ trích xuất đặc trưng vector 16 chiều.
*   Bộ lọc nhanh Tier-1 quét các luật Regex đặc trưng (như từ khóa `vssadmin` hoặc cờ `-enc`).
*   Mô hình LightGBM ước lượng điểm số đe dọa `ml_score`.
*   Nếu điểm số đe dọa vượt ngưỡng `0.8` (cấp độ CRITICAL), **Response Engine** in cảnh báo chi tiết phả hệ tiến trình và chấm dứt tiến trình độc hại bằng API `TerminateProcess()`.

---

## Hiệu năng & Chỉ số Đánh giá

*   **Độ chính xác mô hình**: LightGBM đạt độ chính xác **$96,72\%$** trên tập kiểm thử độc lập (F1-score: `0.965`).
*   **Kích thước mô hình**: Quá trình lượng tử hóa rút gọn tệp ONNX từ 332 KB xuống chỉ còn **110 KB**.
*   **Độ trễ suy diễn**: Mô hình hoàn thành một lượt suy diễn chỉ mất trung bình **$4$ ms**.
*   **Chiếm dụng tài nguyên**: Agent tiêu tốn trung bình `< 5\%` CPU khi chịu tải cao và lượng RAM sử dụng tối đa dưới **40 MB**.
