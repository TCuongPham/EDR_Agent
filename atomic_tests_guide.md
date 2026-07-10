# Hướng dẫn Kiểm thử EDR Agent bằng Atomic Red Team (Invoke-AtomicTest)

Tài liệu này tổng hợp danh sách các lệnh kiểm thử sử dụng module **Atomic Red Team** (`Invoke-AtomicTest`) để giả lập hành vi tấn công trên Windows 11.


## Nhãn: Malware Behavior (Hành vi độc hại)

Các kỹ thuật thực thi lệnh độc hại, thiết lập cơ chế tự khởi động (Persistence), lách bộ lọc bảo mật (Defense Evasion), và tải payload từ internet.

| Mã ATT&CK | Tên kỹ thuật | Lệnh PowerShell (Invoke-Atomic) | Mô tả hành vi (Tiếng Việt) | Các đặc trưng EDR sẽ kích hoạt |
| :--- | :--- | :--- | :--- | :--- |
| **T1059.001** | PowerShell Encoded Command | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | Chạy powershell với tham số `-enc` hoặc `-EncodedCommand` chứa chuỗi Base64 nhằm ẩn giấu nội dung tập lệnh độc hại thực tế.  |
| **T1547.001** | Registry Run Keys Persistence | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | Thêm một chương trình độc hại vào đường dẫn khóa khởi động tự động `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. | `persistence_key_access`, `is_in_temp_path` |
| **T1053.005** | Scheduled Task Creation | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | Tạo một tác vụ lập lịch thông qua `schtasks.exe` để kích hoạt mã độc định kỳ hoặc khi hệ thống khởi động lại. | `cmdline_suspicious_kw_count` (từ khóa: schtasks, create) |
| **T1569.002** | System Service Creation | `Invoke-AtomicTest T1569.002 -TestNumbers 1` | Tạo một Windows Service giả lập bằng lệnh `sc.exe create` chạy dưới đặc quyền hệ thống cao nhất (`LocalSystem`). | `cmdline_suspicious_kw_count`, `token_elevated` |
| **T1218.011** | Rundll32 Proxy Execution | `Invoke-AtomicTest T1218.011 -TestNumbers 2` | Sử dụng công cụ chuẩn `rundll32.exe` để gọi và thực thi một thư viện DLL độc hại được tải xuống từ bên ngoài. | `is_lolbin`, `is_in_temp_path` |
| **T1105** | Ingress Tool Transfer (Download) | `Invoke-AtomicTest T1105 -TestNumbers 7` | Sử dụng PowerShell `Invoke-WebRequest` hoặc `certutil.exe -urlcache` để tải xuống mã độc từ xa về đĩa. | `cmdline_suspicious_kw_count` (từ khóa: iwr, certutil), `network_connect` |


Invoke-AtomicTest T1566.001 -TestNumbers 1
Invoke-AtomicTest T1059.005 -TestNumbers 1 hành vi tấn công Drive-by Download hoặc lừa người dùng click mở file độc từ trình duyệt
Invoke-AtomicTest T1218.005 -TestNumbers 1 Lệnh lạm dụng mshta.exe (Chạy ứng dụng HTML độc hại)
Invoke-AtomicTest T1218.010 -TestNumbers 1 Lệnh lạm dụng regsvr32.exe (Kỹ thuật Squiblydoo)






## Hướng dẫn cài đặt và sử dụng nhanh Invoke-AtomicRedTeam

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
    Invoke-AtomicTest T1566.001 -TestNumbers 1
    ```
3.  Quan sát cửa sổ terminal thứ nhất của `edr_agent.exe` để xem kết quả phân loại thời gian thực (nhãn hiển thị `LOW`, `MEDIUM`, `HIGH` hoặc `CRITICAL`) cùng hành động ngăn chặn tương ứng.
