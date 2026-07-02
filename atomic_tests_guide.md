# Hướng dẫn Kiểm thử EDR Agent bằng Atomic Red Team (Invoke-AtomicTest)

Tài liệu này tổng hợp danh sách các lệnh kiểm thử sử dụng module **Atomic Red Team** (`Invoke-AtomicTest`) để giả lập hành vi tấn công trên Windows 11. Các bài kiểm thử này được phân loại trực tiếp theo 3 nhãn phân loại của mô hình EDR AI Agent: **Credential Access (Đánh cắp định danh)**, **Malware Behavior (Hành vi mã độc)**, và **Benign (Lành tính)**.

---

## 🔑 Nhãn 1: Credential Access (Đánh cắp định danh - T1003)

Đây là các kỹ thuật nhằm trích xuất thông tin đăng nhập, hash mật khẩu hoặc vé Kerberos từ bộ nhớ hoặc cơ sở dữ liệu hệ thống.

| Mã ATT&CK | Tên kỹ thuật | Lệnh PowerShell (Invoke-Atomic) | Mô tả hành vi (Tiếng Việt) | Các đặc trưng EDR sẽ kích hoạt |
| :--- | :--- | :--- | :--- | :--- |
| **T1003.001** | LSASS Memory Dumping | `Invoke-AtomicTest T1003.001 -TestNumbers 1` | Sử dụng tiến trình `rundll32.exe` kết hợp với `comsvcs.dll` để dump bộ nhớ tiến trình LSASS ra file `.dmp` nhằm giải mã mật khẩu. | `lsass_access`, `access_rights_vm_read`, `is_lolbin`, `cmdline_suspicious_kw_count` |
| **T1003.001** | Procdump LSASS | `Invoke-AtomicTest T1003.001 -TestNumbers 2` | Sử dụng công cụ chuẩn `procdump.exe` của Microsoft Sysinternals để ghi đè hoặc trích xuất bộ nhớ của `lsass.exe`. | `lsass_access`, `is_in_temp_path`, `cmdline_suspicious_kw_count` |
| **T1003.002** | Registry Hive SAM/SYSTEM | `Invoke-AtomicTest T1003.002 -TestNumbers 1` | Sử dụng lệnh `reg.exe save` để sao lưu registry hives SAM, SECURITY, và SYSTEM ra thư mục tạm nhằm trích xuất mật khẩu offline. | `reg_sam_security_access`, `is_in_temp_path`, `token_elevated` |
| **T1003.003** | NTDS.dit Extraction | `Invoke-AtomicTest T1003.003 -TestNumbers 1` | Sử dụng công cụ `ntdsutil.exe` tạo bản sao của Active Directory database (`ntds.dit`) chứa toàn bộ hash mật khẩu domain. | `cmdline_suspicious_kw_count` (từ khóa: ntds, secretsdump), `token_elevated` |
| **T1555.003** | Credentials from Browsers | `Invoke-AtomicTest T1555.003 -TestNumbers 1` | Quét và sao chép các tệp cơ sở dữ liệu SQLite lưu trữ mật khẩu của trình duyệt Chrome/Edge/Firefox trong thư mục AppData. | `process_rarity_score`, `parent_is_script_engine`, `lifetime_ms` |

---

## 🦠 Nhãn 2: Malware Behavior (Hành vi độc hại / Thực thi / Duy trì)

Các kỹ thuật thực thi lệnh độc hại, thiết lập cơ chế tự khởi động (Persistence), lách bộ lọc bảo mật (Defense Evasion), và tải payload từ internet.

| Mã ATT&CK | Tên kỹ thuật | Lệnh PowerShell (Invoke-Atomic) | Mô tả hành vi (Tiếng Việt) | Các đặc trưng EDR sẽ kích hoạt |
| :--- | :--- | :--- | :--- | :--- |
| **T1059.001** | PowerShell Encoded Command | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | Chạy powershell với tham số `-enc` hoặc `-EncodedCommand` chứa chuỗi Base64 nhằm ẩn giấu nội dung tập lệnh độc hại thực tế. | `parent_is_browser` (nếu chạy từ Office), `cmdline_suspicious_kw_count`, `process_rarity_score` |
| **T1547.001** | Registry Run Keys Persistence | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | Thêm một chương trình độc hại vào đường dẫn khóa khởi động tự động `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. | `persistence_key_access`, `is_in_temp_path` |
| **T1053.005** | Scheduled Task Creation | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | Tạo một tác vụ lập lịch thông qua `schtasks.exe` để kích hoạt mã độc định kỳ hoặc khi hệ thống khởi động lại. | `cmdline_suspicious_kw_count` (từ khóa: schtasks, create) |
| **T1569.002** | System Service Creation | `Invoke-AtomicTest T1569.002 -TestNumbers 1` | Tạo một Windows Service giả lập bằng lệnh `sc.exe create` chạy dưới đặc quyền hệ thống cao nhất (`LocalSystem`). | `cmdline_suspicious_kw_count`, `token_elevated` |
| **T1218.011** | Rundll32 Proxy Execution | `Invoke-AtomicTest T1218.011 -TestNumbers 1` | Sử dụng công cụ chuẩn `rundll32.exe` để gọi và thực thi một thư viện DLL độc hại được tải xuống từ bên ngoài. | `is_lolbin`, `is_in_temp_path` |
| **T1105** | Ingress Tool Transfer (Download) | `Invoke-AtomicTest T1105 -TestNumbers 1` | Sử dụng PowerShell `Invoke-WebRequest` hoặc `certutil.exe -urlcache` để tải xuống mã độc từ xa về đĩa. | `cmdline_suspicious_kw_count` (từ khóa: iwr, certutil), `network_connect` |

---

## 🟢 Nhãn 3: Benign (Hành vi lành tính / Dò quét hệ thống chuẩn)

Các hoạt động thường ngày của Quản trị viên (SysAdmin) hoặc các công cụ giám sát hiệu năng hệ thống chuẩn. EDR sẽ nhận diện và dán nhãn lành tính nhằm giảm tỉ lệ cảnh báo giả (False Positive).

| Mã ATT&CK | Tên kỹ thuật | Lệnh PowerShell (Invoke-Atomic) | Mô tả hành vi (Tiếng Việt) | Các đặc trưng EDR sẽ kích hoạt |
| :--- | :--- | :--- | :--- | :--- |
| **T1082** | System Info Discovery | `Invoke-AtomicTest T1082 -TestNumbers 1` | Lấy thông tin cấu hình phần cứng, phiên bản hệ điều hành và card mạng thông qua lệnh chuẩn `systeminfo`. | `lifetime_ms` (ngắn), `is_in_system_path` |
| **T1057** | Process Discovery | `Invoke-AtomicTest T1057 -TestNumbers 1` | Liệt kê danh sách các ứng dụng đang chạy trong Windows thông qua lệnh `tasklist` hoặc lệnh `Get-Process`. | `lifetime_ms`, `is_in_system_path` |
| **T1083** | File & Directory Discovery | `Invoke-AtomicTest T1083 -TestNumbers 1` | Sử dụng lệnh `dir` hoặc `Get-ChildItem` quét cấu trúc tệp tin trong thư mục người dùng tìm kiếm tài liệu nhạy cảm. | `lifetime_ms` |
| **T1049** | System Network Connections | `Invoke-AtomicTest T1049 -TestNumbers 1` | Xem danh sách các cổng kết nối mạng đang hoạt động trên máy thông qua lệnh chuẩn `netstat -ano`. | `lifetime_ms`, `is_in_system_path` |

---

## 🛠️ Hướng dẫn cài đặt và sử dụng nhanh Invoke-AtomicRedTeam

Nếu máy thử nghiệm của bạn chưa cài đặt Atomic Red Team, bạn có thể thiết lập nhanh bằng các lệnh PowerShell sau (chạy với quyền **Administrator** và tắt tạm thời Windows Defender Real-time):

```powershell
# 1. Cho phép chạy script bên thứ ba
Set-ExecutionPolicy Bypass -Force

# 2. Cài đặt framework và tải dữ liệu kiểm thử
Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force
Import-Module Invoke-AtomicRedTeam

# 3. Tải toàn bộ thư viện kịch bản tấn công (Atomics) về máy
Install-AtomicsFolder
```

### Cách chạy kiểm thử đối chiếu với EDR Agent:
1.  Bật EDR Agent ở terminal thứ nhất:
    ```powershell
    cd D:\Universe\VCS\EDR_AI_Agent\build\agent\Release
    .\edr_agent.exe D:\Universe\VCS\EDR_AI_Agent\agent\configs\agent_config.json
    ```
2.  Mở terminal thứ hai (PowerShell Admin) và chạy lệnh test, ví dụ:
    ```powershell
    # Chạy thử nghiệm dump LSASS (Nhãn Credential Access)
    Invoke-AtomicTest T1003.001 -TestNumbers 1
    ```
3.  Quan sát cửa sổ terminal thứ nhất của `edr_agent.exe` để xem kết quả phân loại thời gian thực (nhãn hiển thị `LOW`, `MEDIUM`, `HIGH` hoặc `CRITICAL`) cùng hành động ngăn chặn tương ứng.
