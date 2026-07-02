# Benchmark Specification — EDR AI Agent
## Tiêu chí Đánh giá Hiệu năng & Kịch bản Kiểm thử

> **Phiên bản**: v1.0 | **Ngày**: 2026-06-07  
> **Mục đích**: Định nghĩa phương pháp đo hiệu năng hệ thống và kịch bản test bảo mật

---

## 1. Tổng quan Benchmark Framework

```
BENCHMARK FRAMEWORK
│
├── PERFORMANCE BENCHMARKS (Hiệu năng hệ thống)
│   ├── CPU Usage           → < 5% average idle, < 15% peak
│   ├── RAM Usage           → < 100 MB Working Set
│   ├── Disk I/O            → < 5 MB/s average write
│   ├── Inference Latency   → < 50ms per event (FP32), < 20ms (INT8)
│   ├── Event Throughput    → > 1,000 events/second sustained
│   └── Startup Time        → < 3 seconds to fully operational
│
├── DETECTION BENCHMARKS (Chất lượng phát hiện)
│   ├── Detection Rate      → > 85% (True Positive Rate)
│   ├── False Positive Rate → < 5% on benign workload
│   ├── Alert Latency       → < 500ms từ event đến alert
│   └── MITRE Coverage      → > 15 techniques detected
│
└── STRESS BENCHMARKS (Giới hạn hệ thống)
    ├── Ransomware burst     → 10,000 file events/min
    ├── Memory pressure      → 8GB RAM system under load
    └── Event flood          → 50,000 events/sec injection
```

---

## 2. Performance Benchmarks

### 2.1 CPU Usage Benchmark

#### Phương pháp đo

```powershell
# Script: tests/benchmark/measure_cpu.ps1
# Chạy trong PowerShell với quyền Administrator

param(
    [int]$DurationSeconds = 300,  # 5 phút measurement
    [string]$AgentProcessName = "edr-agent",
    [string]$OutputFile = "benchmark_results\cpu_usage.csv"
)

# Tạo thư mục output
New-Item -ItemType Directory -Force -Path "benchmark_results" | Out-Null

# Khởi động agent nếu chưa chạy
# Start-Process -FilePath ".\agent\edr-agent.exe" -ArgumentList "--config .\agent\configs\config.yaml"
Start-Sleep -Seconds 5  # Chờ agent khởi động ổn định

Write-Host "Starting CPU benchmark for $DurationSeconds seconds..."
$results = @()

$endTime = (Get-Date).AddSeconds($DurationSeconds)
while ((Get-Date) -lt $endTime) {
    $proc = Get-Process -Name $AgentProcessName -ErrorAction SilentlyContinue
    if ($proc) {
        $cpuUsage = $proc.CPU
        $results += [PSCustomObject]@{
            Timestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff")
            CPU_Percent     = [Math]::Round((Get-Counter "\Process($AgentProcessName)\% Processor Time").CounterSamples[0].CookedValue, 2)
            WorkingSet_MB   = [Math]::Round($proc.WorkingSet64 / 1MB, 2)
            PrivateBytes_MB = [Math]::Round($proc.PrivateMemorySize64 / 1MB, 2)
            Handles         = $proc.HandleCount
            Threads         = $proc.Threads.Count
        }
    }
    Start-Sleep -Milliseconds 1000  # Sample mỗi 1 giây
}

# Export CSV
$results | Export-Csv -Path $OutputFile -NoTypeInformation

# Tính thống kê
$cpuValues = $results | Select-Object -ExpandProperty CPU_Percent
$ramValues = $results | Select-Object -ExpandProperty WorkingSet_MB

Write-Host "`n=== CPU BENCHMARK RESULTS ==="
Write-Host ("CPU Average:   {0:F2}%" -f ($cpuValues | Measure-Object -Average).Average)
Write-Host ("CPU Peak:      {0:F2}%" -f ($cpuValues | Measure-Object -Maximum).Maximum)
Write-Host ("CPU Std Dev:   {0:F2}%" -f ($cpuValues | ForEach-Object { [Math]::Pow($_ - ($cpuValues | Measure-Object -Average).Average, 2) } | Measure-Object -Average | ForEach-Object { [Math]::Sqrt($_.Average) }))
Write-Host "`n=== RAM BENCHMARK RESULTS ==="
Write-Host ("RAM Average:   {0:F2} MB" -f ($ramValues | Measure-Object -Average).Average)
Write-Host ("RAM Peak:      {0:F2} MB" -f ($ramValues | Measure-Object -Maximum).Maximum)

# Pass/Fail assessment
$avgCPU = ($cpuValues | Measure-Object -Average).Average
$peakRAM = ($ramValues | Measure-Object -Maximum).Maximum

if ($avgCPU -lt 5.0) {
    Write-Host "`n[PASS] CPU Average: $([Math]::Round($avgCPU,2))% < 5% target" -ForegroundColor Green
} else {
    Write-Host "`n[FAIL] CPU Average: $([Math]::Round($avgCPU,2))% >= 5% target" -ForegroundColor Red
}

if ($peakRAM -lt 100.0) {
    Write-Host "[PASS] RAM Peak: $([Math]::Round($peakRAM,2)) MB < 100 MB target" -ForegroundColor Green
} else {
    Write-Host "[FAIL] RAM Peak: $([Math]::Round($peakRAM,2)) MB >= 100 MB target" -ForegroundColor Red
}
```

#### Kịch bản đo CPU

```
Scenario 1: IDLE BASELINE (phải < 2% CPU)
- Agent chạy, không có activity đặc biệt
- Chỉ Windows background processes
- Duration: 10 phút

Scenario 2: NORMAL WORKLOAD (phải < 5% CPU)
- Mở trình duyệt, browse web
- Gõ văn bản trong Word/Notepad
- Chạy một số commands trong PowerShell
- Duration: 10 phút

Scenario 3: HEAVY WORKLOAD (phải < 10% CPU)
- Compile code (MSBuild, CMake build)
- Extract large ZIP archive
- Run npm install
- Duration: 5 phút

Scenario 4: DETECTION EVENT (spike < 15% CPU, spike duration < 1s)
- Trigger một Atomic Red Team test
- Đo CPU spike khi inference xảy ra
```

---

### 2.2 Inference Latency Benchmark

```cpp
// tests/benchmark/inference_benchmark.cpp
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <numeric>
#include <algorithm>
#include "onnx_inferencer.h"
#include "ringbuffer.h"

// 1. BenchmarkONNXInference đo latency của một lần inference đơn
void BenchmarkONNXInference(const std::wstring& modelPath) {
    ONNXInferencer inferencer(modelPath);

    std::vector<float> features(64);
    std::random_device rd;
    std::mt19939 gen(rd());
    std::uniform_real_distribution<float> dis(0.0f, 1.0f);

    for (int i = 0; i < 64; ++i) {
        features[i] = dis(gen);
    }

    const int iterations = 10000;
    std::vector<double> latencies;
    latencies.reserve(iterations);

    // Warmup
    for (int i = 0; i < 100; ++i) {
        inferencer.Infer(features);
    }

    // Measure
    for (int i = 0; i < iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        inferencer.Infer(features);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        latencies.push_back(elapsed.count());
    }

    // Tính toán Percentiles
    std::sort(latencies.begin(), latencies.end());
    double p50 = latencies[iterations * 50 / 100];
    double p95 = latencies[iterations * 95 / 100];
    double p99 = latencies[iterations * 99 / 100];
    double p999 = latencies[iterations * 999 / 1000];

    std::cout << "Inference Latency (n=" << iterations << ") in microseconds:\n";
    std::cout << "  P50:   " << p50 << " us (" << p50 / 1000.0 << " ms)\n";
    std::cout << "  P95:   " << p95 << " us (" << p95 / 1000.0 << " ms)\n";
    std::cout << "  P99:   " << p99 << " us (" << p99 / 1000.0 << " ms) -> Target: < 50ms\n";
    std::cout << "  P99.9: " << p999 << " us (" << p999 / 1000.0 << " ms)\n";
}

// 2. BenchmarkRingBufferThroughput đo throughput của event pipeline
void BenchmarkRingBufferThroughput() {
    RingBuffer ringBuffer(65536);
    const int eventCount = 100000;

    // Thread Producer đẩy event vào
    std::thread producer([&]() {
        for (int i = 0; i < eventCount; ++i) {
            auto evt = std::make_shared<NormalizedEvent>();
            evt->pid = i % 1000;
            while (!ringBuffer.Push(evt)) {
                std::this_thread::yield();
            }
        }
    });

    // Thread Consumer lấy event ra & đo throughput
    auto start = std::chrono::high_resolution_clock::now();
    int received = 0;
    while (received < eventCount) {
        auto evt = ringBuffer.Pop();
        if (evt) {
            received++;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    if (producer.joinable()) {
        producer.join();
    }

    double throughput = eventCount / elapsed.count();
    std::cout << "Ring Buffer Throughput: " << throughput << " events/sec\n";
    if (throughput >= 1000.0) {
        std::cout << "[PASS] Throughput exceeds 1,000 events/sec target\n";
    } else {
        std::cout << "[FAIL] Throughput below target\n";
    }
}
```

---

### 2.3 Disk I/O & Startup Benchmark

```powershell
# tests/benchmark/measure_disk_io.ps1

# Đo disk I/O của agent trong 60 giây
$agentPID = (Get-Process "edr-agent").Id
$counters = @(
    "\Process(edr-agent)\IO Write Bytes/sec",
    "\Process(edr-agent)\IO Read Bytes/sec",
    "\Process(edr-agent)\IO Data Bytes/sec"
)

$samples = Get-Counter -Counter $counters -SampleInterval 1 -MaxSamples 60

$writeRates = $samples.CounterSamples | 
    Where-Object { $_.Path -like "*Write*" } | 
    Select-Object -ExpandProperty CookedValue

$avgWriteMBps = ($writeRates | Measure-Object -Average).Average / 1MB
Write-Host "Average Disk Write: $([Math]::Round($avgWriteMBps, 3)) MB/s"

if ($avgWriteMBps -lt 5.0) {
    Write-Host "[PASS] Disk Write < 5 MB/s target" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Disk Write >= 5 MB/s target" -ForegroundColor Red
}

# Đo startup time
Write-Host "`nMeasuring startup time..."
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$proc = Start-Process -FilePath ".\agent\edr-agent.exe" -PassThru

# Chờ đến khi agent sẵn sàng (kiểm tra health endpoint hoặc named pipe)
do {
    Start-Sleep -Milliseconds 100
    $pipe = [System.IO.Directory]::GetFiles("\\.\pipe\", "edr-agent-*")
} while ($pipe.Count -eq 0 -and $stopwatch.Elapsed.TotalSeconds -lt 30)

$stopwatch.Stop()
Write-Host "Startup Time: $($stopwatch.Elapsed.TotalMilliseconds) ms"

if ($stopwatch.Elapsed.TotalSeconds -lt 3) {
    Write-Host "[PASS] Startup < 3 seconds target" -ForegroundColor Green
}
```

---

## 3. Detection Benchmarks — Atomic Red Team Test Suite

### 3.1 Test Matrix

```
MITRE ATT&CK Coverage — Danh sách kịch bản bắt buộc test

┌──────────┬──────────────────────────────────┬────────┬──────────────┬──────────┐
│ ATT&CK ID│ Technique Name                   │ Tool   │ Expected Det │ Priority │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│ EXECUTION │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│T1059.001 │ PowerShell Execution              │ ART    │ HIGH         │ P0       │
│T1059.001 │ Encoded PowerShell                │ ART    │ CRITICAL     │ P0       │
│T1059.003 │ Windows Command Shell             │ ART    │ MEDIUM       │ P1       │
│T1204.002 │ Malicious File (macro)            │ ART    │ HIGH         │ P0       │
│T1218.011 │ Rundll32 LOLBin                   │ ART    │ HIGH         │ P0       │
│T1218.010 │ Regsvr32 LOLBin                   │ ART    │ HIGH         │ P1       │
│T1218.005 │ Mshta LOLBin                      │ ART    │ HIGH         │ P1       │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│ PERSISTENCE │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│T1547.001 │ Registry Run Key                  │ ART    │ HIGH         │ P0       │
│T1053.005 │ Scheduled Task                    │ ART    │ HIGH         │ P0       │
│T1543.003 │ Windows Service Creation          │ ART    │ HIGH         │ P1       │
│T1546.015 │ COM Object Hijacking              │ ART    │ MEDIUM       │ P2       │
│T1547.009 │ Shortcut Modification             │ ART    │ MEDIUM       │ P2       │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│ PRIVILEGE ESCALATION │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│T1548.002 │ UAC Bypass via fodhelper          │ ART    │ HIGH         │ P0       │
│T1134.001 │ Token Impersonation               │ ART    │ MEDIUM       │ P1       │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│ DEFENSE EVASION │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│T1027.010 │ Command Obfuscation               │ ART    │ HIGH         │ P0       │
│T1055.001 │ Process Injection (DLL)           │ ART    │ HIGH         │ P0       │
│T1070.004 │ File Deletion                     │ ART    │ MEDIUM       │ P1       │
│T1036.005 │ Process Masquerading              │ ART    │ MEDIUM       │ P1       │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│ CREDENTIAL ACCESS │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│T1003.001 │ LSASS Memory Dump (procdump)      │ ART    │ CRITICAL     │ P0       │
│T1003.001 │ LSASS Memory Dump (comsvcs.dll)   │ ART    │ CRITICAL     │ P0       │
│T1552.001 │ Credentials in Files              │ ART    │ MEDIUM       │ P1       │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│ DISCOVERY │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│T1082     │ System Information Discovery      │ ART    │ LOW          │ P2       │
│T1083     │ File and Directory Discovery      │ ART    │ LOW          │ P2       │
│T1016     │ System Network Config Discovery   │ ART    │ LOW          │ P2       │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│ LATERAL MOVEMENT │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│T1021.002 │ SMB/Admin Shares (PsExec-like)    │ ART    │ HIGH         │ P1       │
│T1047     │ WMI Execution                     │ ART    │ HIGH         │ P0       │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│ IMPACT │
├──────────┼──────────────────────────────────┼────────┼──────────────┼──────────┤
│T1486     │ Data Encrypted (Ransomware sim)   │ ART    │ CRITICAL     │ P0       │
│T1490     │ Shadow Copy Deletion              │ ART    │ CRITICAL     │ P0       │
│T1489     │ Service Stop                      │ ART    │ HIGH         │ P1       │
└──────────┴──────────────────────────────────┴────────┴──────────────┴──────────┘

Tổng: 29 techniques
Mục tiêu: Detect >= 25/29 (86%)
P0 (bắt buộc): 15 techniques → phải detect 100%
```

### 3.2 Automated Test Runner

```powershell
# tests/atomic_red_team/run_detection_tests.ps1
# Chạy toàn bộ Atomic Red Team test suite và thu thập kết quả

param(
    [string]$AgentLogPath = "C:\ProgramData\EDRAgent\alerts.jsonl",
    [string]$ResultsOutput = "benchmark_results\detection_results.json",
    [int]$WaitSecondsAfterTest = 30
)

# Import Invoke-AtomicRedTeam
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

# Danh sách tests cần chạy (theo thứ tự từ ít nguy hiểm → nguy hiểm)
$testCases = @(
    @{ TechniqueID = "T1059.001"; TestNum = 1; Name = "PS_BasicExec";          Priority = "P1" },
    @{ TechniqueID = "T1059.001"; TestNum = 2; Name = "PS_EncodedCommand";     Priority = "P0" },
    @{ TechniqueID = "T1059.003"; TestNum = 1; Name = "CMD_Exec";              Priority = "P1" },
    @{ TechniqueID = "T1218.011"; TestNum = 1; Name = "Rundll32_LOLBin";       Priority = "P0" },
    @{ TechniqueID = "T1218.010"; TestNum = 1; Name = "Regsvr32_LOLBin";       Priority = "P1" },
    @{ TechniqueID = "T1547.001"; TestNum = 1; Name = "Registry_RunKey";       Priority = "P0" },
    @{ TechniqueID = "T1053.005"; TestNum = 1; Name = "ScheduledTask";         Priority = "P0" },
    @{ TechniqueID = "T1543.003"; TestNum = 1; Name = "ServiceCreation";       Priority = "P1" },
    @{ TechniqueID = "T1548.002"; TestNum = 1; Name = "UAC_Bypass_fodhelper";  Priority = "P0" },
    @{ TechniqueID = "T1027.010"; TestNum = 1; Name = "CmdObfuscation";        Priority = "P0" },
    @{ TechniqueID = "T1055.001"; TestNum = 1; Name = "DLL_Injection";         Priority = "P0" },
    @{ TechniqueID = "T1003.001"; TestNum = 1; Name = "LSASS_Procdump";        Priority = "P0" },
    @{ TechniqueID = "T1003.001"; TestNum = 2; Name = "LSASS_Comsvcs";         Priority = "P0" },
    @{ TechniqueID = "T1047";     TestNum = 1; Name = "WMI_Execution";         Priority = "P0" },
    @{ TechniqueID = "T1486";     TestNum = 1; Name = "Ransomware_FileEncrypt"; Priority = "P0" },
    @{ TechniqueID = "T1490";     TestNum = 1; Name = "ShadowCopy_Delete";     Priority = "P0" }
)

$results = @()
$alertsBefore = 0

Write-Host "=== EDR DETECTION BENCHMARK ===" -ForegroundColor Cyan
Write-Host "Running $($testCases.Count) test cases..."
Write-Host ""

foreach ($test in $testCases) {
    Write-Host "[$($test.Priority)] Testing: $($test.Name) ($($test.TechniqueID))..." -NoNewline
    
    # Ghi nhớ số alerts trước test
    $alertsBefore = (Get-Content $AgentLogPath -ErrorAction SilentlyContinue | 
                     Measure-Object -Line).Lines
    
    $startTime = Get-Date
    
    try {
        # Chạy Atomic Red Team test (với timeout 60 giây)
        $job = Start-Job -ScriptBlock {
            param($techID, $testNum)
            Invoke-AtomicTest $techID -TestNumbers $testNum -Confirm:$false 2>&1
        } -ArgumentList $test.TechniqueID, $test.TestNum
        
        $completed = Wait-Job $job -Timeout 60
        if (-not $completed) {
            Stop-Job $job
            Write-Host " [TIMEOUT]" -ForegroundColor Yellow
        }
        Remove-Job $job -Force
        
    } catch {
        Write-Host " [ERROR: $_]" -ForegroundColor Yellow
    }
    
    # Chờ agent xử lý và generate alert
    Start-Sleep -Seconds $WaitSecondsAfterTest
    
    # Kiểm tra alerts mới được generate
    $alertsAfter = (Get-Content $AgentLogPath -ErrorAction SilentlyContinue | 
                    Measure-Object -Line).Lines
    $newAlerts = $alertsAfter - $alertsBefore
    
    # Parse alerts để xem có đúng technique không
    $detectionFound = $false
    $alertDetails = @()
    
    if ($newAlerts -gt 0) {
        $recentAlerts = Get-Content $AgentLogPath | 
            Select-Object -Last $newAlerts |
            ForEach-Object { $_ | ConvertFrom-Json -ErrorAction SilentlyContinue }
        
        foreach ($alert in $recentAlerts) {
            $alertDetails += [PSCustomObject]@{
                ThreatScore  = $alert.threat_score
                ThreatLevel  = $alert.threat_level
                Technique    = $alert.technique_id
                ProcessChain = ($alert.process_chain -join " → ")
            }
        }
        $detectionFound = $true
    }
    
    $elapsed = (Get-Date) - $startTime
    
    # Record result
    $result = [PSCustomObject]@{
        TechniqueID   = $test.TechniqueID
        Name          = $test.Name
        Priority      = $test.Priority
        Detected      = $detectionFound
        NewAlerts     = $newAlerts
        ElapsedSec    = [Math]::Round($elapsed.TotalSeconds, 2)
        AlertDetails  = $alertDetails
    }
    $results += $result
    
    # Print result
    if ($detectionFound) {
        Write-Host " [DETECTED] ($newAlerts alerts)" -ForegroundColor Green
    } else {
        Write-Host " [MISSED]" -ForegroundColor Red
    }
    
    # Cleanup sau mỗi test (restore system state)
    try {
        Invoke-AtomicTest $test.TechniqueID -TestNumbers $test.TestNum -Cleanup -Confirm:$false 2>&1 | Out-Null
    } catch {}
    
    # Snapshot VM nếu cần (sau mỗi 5 tests)
}

# ─── TÍNH THỐNG KÊ ───
$total = $results.Count
$detected = ($results | Where-Object { $_.Detected }).Count
$missed = $total - $detected
$detectionRate = [Math]::Round($detected / $total * 100, 1)

$p0Tests = $results | Where-Object { $_.Priority -eq "P0" }
$p0Detected = ($p0Tests | Where-Object { $_.Detected }).Count
$p0Rate = [Math]::Round($p0Detected / $p0Tests.Count * 100, 1)

Write-Host ""
Write-Host "=== FINAL RESULTS ===" -ForegroundColor Cyan
Write-Host ("Overall Detection Rate: {0}/{1} ({2}%)" -f $detected, $total, $detectionRate)
Write-Host ("P0 (Critical) Detection: {0}/{1} ({2}%)" -f $p0Detected, $p0Tests.Count, $p0Rate)

# Pass/Fail
if ($detectionRate -ge 85.0) {
    Write-Host "[PASS] Overall detection rate >= 85% target" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Overall detection rate < 85% target" -ForegroundColor Red
}

if ($p0Rate -ge 100.0) {
    Write-Host "[PASS] All P0 critical techniques detected" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Some P0 critical techniques missed!" -ForegroundColor Red
    $p0Tests | Where-Object { -not $_.Detected } | ForEach-Object {
        Write-Host "  MISSED: $($_.TechniqueID) - $($_.Name)" -ForegroundColor Red
    }
}

# Export JSON
$summary = @{
    timestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    total_tests     = $total
    detected        = $detected
    missed          = $missed
    detection_rate  = $detectionRate
    p0_rate         = $p0Rate
    details         = $results
}
$summary | ConvertTo-Json -Depth 5 | Out-File $ResultsOutput
Write-Host "`nResults saved to: $ResultsOutput"
```

---

### 3.3 False Positive Benchmark

```powershell
# tests/benchmark/false_positive_test.ps1
# Đo False Positive Rate trong 4 giờ sử dụng thông thường

param(
    [int]$DurationHours = 4,
    [string]$AgentLogPath = "C:\ProgramData\EDRAgent\alerts.jsonl"
)

Write-Host "=== FALSE POSITIVE BENCHMARK ===" -ForegroundColor Cyan
Write-Host "Duration: $DurationHours hours of NORMAL workload"
Write-Host "Simulating typical enterprise user activity..."

$alertsBefore = (Get-Content $AgentLogPath -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
$startTime = Get-Date

# Simulate normal user workload
$workloadScript = {
    $endTime = (Get-Date).AddHours($args[0])
    while ((Get-Date) -lt $endTime) {
        # Mở và đóng ứng dụng thông thường
        $activities = @(
            { Start-Process notepad -Wait:$false; Start-Sleep 10; Stop-Process -Name notepad -ErrorAction SilentlyContinue },
            { Start-Process calc -Wait:$false; Start-Sleep 5; Stop-Process -Name calculator -ErrorAction SilentlyContinue },
            { Get-ChildItem C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue | Select-Object -First 100 | Out-Null },
            { Invoke-WebRequest "https://www.microsoft.com" -UseBasicParsing -TimeoutSec 10 | Out-Null },
            { $files = Get-Item C:\Users\$env:USERNAME\Documents\* -ErrorAction SilentlyContinue },
            { Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Out-Null },
            { Get-EventLog -LogName System -Newest 10 -ErrorAction SilentlyContinue | Out-Null }
        )
        
        $randomActivity = $activities | Get-Random
        & $randomActivity
        Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 120)
    }
}

# Chạy workload trong background
$workloadJob = Start-Job -ScriptBlock $workloadScript -ArgumentList $DurationHours

Write-Host "Workload started. Monitoring for $DurationHours hours..."
Write-Host "Press Ctrl+C to stop early."

Wait-Job $workloadJob -Timeout ($DurationHours * 3600 + 60) | Out-Null

# Đếm false positives
$alertsAfter = (Get-Content $AgentLogPath -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
$totalAlerts = $alertsAfter - $alertsBefore

# Parse alerts và phân loại
$recentAlerts = Get-Content $AgentLogPath | Select-Object -Last ($totalAlerts) |
    ForEach-Object { $_ | ConvertFrom-Json -ErrorAction SilentlyContinue } |
    Where-Object { $_ -ne $null }

$highAlerts = ($recentAlerts | Where-Object { $_.threat_level -in "HIGH","CRITICAL" }).Count
$medAlerts  = ($recentAlerts | Where-Object { $_.threat_level -eq "MEDIUM" }).Count
$lowAlerts  = ($recentAlerts | Where-Object { $_.threat_level -eq "LOW" }).Count

$elapsedHours = ((Get-Date) - $startTime).TotalHours
$alertsPerHour = [Math]::Round($totalAlerts / $elapsedHours, 1)

Write-Host "`n=== FALSE POSITIVE RESULTS ===" -ForegroundColor Cyan
Write-Host ("Duration: {0:F1} hours" -f $elapsedHours)
Write-Host "Total Alerts: $totalAlerts ($alertsPerHour alerts/hour)"
Write-Host "  HIGH/CRITICAL: $highAlerts"
Write-Host "  MEDIUM:        $medAlerts"
Write-Host "  LOW:           $lowAlerts"

# Acceptance criteria
$highFPRate = $highAlerts / ($elapsedHours * 60)  # Per minute
if ($highAlerts -eq 0) {
    Write-Host "[PASS] Zero HIGH/CRITICAL false positives" -ForegroundColor Green
} elseif ($highAlerts -le 2) {
    Write-Host "[WARN] $highAlerts HIGH/CRITICAL alerts in $([Math]::Round($elapsedHours,1))h - review needed" -ForegroundColor Yellow
} else {
    Write-Host "[FAIL] $highAlerts HIGH/CRITICAL false positives exceeds threshold" -ForegroundColor Red
}

if ($alertsPerHour -le 10) {
    Write-Host "[PASS] Alert rate $alertsPerHour/hour is acceptable" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Alert rate $alertsPerHour/hour is too noisy" -ForegroundColor Red
}
```

---

## 4. Stress Benchmarks

### 4.1 Ransomware Burst Test

```powershell
# tests/benchmark/ransomware_burst_test.ps1
# Mô phỏng burst file modification của ransomware

param(
    [int]$FileCount = 500,
    [string]$TestDir = "C:\Temp\RansomwareTest"
)

# Tạo thư mục test với files ngẫu nhiên
New-Item -ItemType Directory -Force $TestDir | Out-Null
Write-Host "Creating $FileCount test files..."
for ($i = 0; $i -lt $FileCount; $i++) {
    $content = [System.Text.Encoding]::UTF8.GetBytes(("A" * (Get-Random -Min 1024 -Max 10240)))
    [System.IO.File]::WriteAllBytes("$TestDir\file_$i.docx", $content)
}

Write-Host "Starting ransomware simulation (mass file rewrite + rename)..."
$alertsBefore = (Get-Content "C:\ProgramData\EDRAgent\alerts.jsonl" | Measure-Object -Line).Lines

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Simulate: overwrite files với random (high-entropy) content, then rename
for ($i = 0; $i -lt $FileCount; $i++) {
    $encryptedContent = New-Object byte[] 4096
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($encryptedContent)
    [System.IO.File]::WriteAllBytes("$TestDir\file_$i.docx", $encryptedContent)
    Rename-Item "$TestDir\file_$i.docx" "$TestDir\file_$i.docx.LOCKED" -ErrorAction SilentlyContinue
}

$stopwatch.Stop()
$elapsedSec = $stopwatch.Elapsed.TotalSeconds

Write-Host "Ransomware simulation complete: $FileCount files in $([Math]::Round($elapsedSec,2))s"
Write-Host ("Rate: {0:F0} files/sec" -f ($FileCount / $elapsedSec))

# Chờ agent detect
Start-Sleep -Seconds 10

$alertsAfter = (Get-Content "C:\ProgramData\EDRAgent\alerts.jsonl" | Measure-Object -Line).Lines
$newAlerts = $alertsAfter - $alertsBefore

if ($newAlerts -gt 0) {
    Write-Host "[PASS] Agent detected ransomware behavior ($newAlerts alerts)" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Agent did NOT detect ransomware simulation!" -ForegroundColor Red
}

# Đo impact lên agent CPU trong thời gian burst
Write-Host "Agent CPU during burst: (check benchmark_results\cpu_during_burst.csv)"

# Cleanup
Remove-Item $TestDir -Recurse -Force
```

### 4.2 Event Flood Test (Agent Stability)

```cpp
// tests/benchmark/event_flood_test.cpp
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <memory>
#include "ringbuffer.h"

// TestEventFloodStability kiểm tra agent không crash/deadlock khi bị flood
void TestEventFloodStability() {
    RingBuffer ringBuffer(65536);
    const int numThreads = 10;
    const int eventsPerThread = 10000;
    const int totalEvents = numThreads * eventsPerThread;

    std::atomic<uint64_t> produced{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> consumed{0};
    std::atomic<bool> consumerRunning{true};

    // Thread Consumer chạy bất đồng bộ để Pop sự kiện ra
    std::thread consumer([&]() {
        while (consumerRunning || consumed < (produced - dropped)) {
            auto evt = ringBuffer.Pop();
            if (evt) {
                consumed++;
            } else {
                std::this_thread::yield();
            }
        }
    });

    auto start = std::chrono::high_resolution_clock::now();
    
    // Tạo 10 Thread Producer chạy song song bắn phá queue
    std::vector<std::thread> producers;
    for (int g = 0; g < numThreads; ++g) {
        producers.emplace_back([&, g]() {
            for (int i = 0; i < eventsPerThread; ++i) {
                auto evt = std::make_shared<NormalizedEvent>();
                evt->pid = g * 1000 + i;
                evt->eventType = "ProcessCreate";
                if (ringBuffer.Push(evt)) {
                    produced++;
                } else {
                    dropped++;
                }
            }
        });
    }

    // Chờ producers xong
    for (auto& t : producers) {
        t.join();
    }

    // Dừng consumer
    consumerRunning = false;
    if (consumer.joinable()) {
        consumer.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    double prodRate = produced / elapsed.count();
    double dropRate = (static_cast<double>(dropped) / (produced + dropped)) * 100.0;

    std::cout << "Event Flood Test Results:\n";
    std::cout << "  Produced:   " << produced << " events in " << elapsed.count() << " seconds\n";
    std::cout << "  Production Rate: " << prodRate << " events/sec\n";
    std::cout << "  Dropped:    " << dropped << " (" << dropRate << "%)\n";
}
```

---

## 5. Alert Latency Benchmark

```cpp
// tests/benchmark/alert_latency_benchmark.cpp
#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <cstring>
#include "normalizer.h"
#include "rule_engine.h"
#include "features.h"
#include "onnx_inferencer.h"

// TestAlertLatencyP99 đo độ trễ đầu-cuối từ event nhận được đến alert
void TestAlertLatencyP99() {
    Normalizer normalizer;
    RuleEngine ruleEngine;
    SlidingWindowAggregator featureEng;
    ONNXInferencer onnx(L"models/edr_model_int8.onnx");

    RawEvent maliciousEvent;
    maliciousEvent.eventType = EventType::EventProcessCreate;
    std::strcpy(maliciousEvent.processName, "powershell.exe");
    std::strcpy(maliciousEvent.commandLine, "powershell.exe -ExecutionPolicy Bypass -EncodedCommand ...");

    const int iterations = 1000;
    std::vector<double> latencies;
    latencies.reserve(iterations);

    for (int i = 0; i < iterations; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        
        // Stage 1: Normalize
        auto normalized = normalizer.Normalize(maliciousEvent);
        
        // Stage 2: Rule check
        RuleDecision decision = ruleEngine.Evaluate(normalized);
        
        // Stage 3: Feature extraction
        featureEng.Update(normalized);
        auto featureVec = featureEng.GetFeatureVector(normalized->pid);
        
        // Stage 4: Inference
        float score = onnx.Infer(featureVec);
        
        // Stage 5: Response decision
        // (response handler would act ở đây)
        
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        latencies.push_back(elapsed.count());
    }
    
    // Tính toán thống kê
    double sum = std::accumulate(latencies.begin(), latencies.end(), 0.0);
    double avgLatency = sum / iterations;
    double maxLatency = *std::max_element(latencies.begin(), latencies.end());
    
    std::cout << "Alert End-to-End Latency (n=" << iterations << "):\n";
    std::cout << "  Average: " << avgLatency << " ms (Target: < 500ms)\n";
    std::cout << "  Maximum: " << maxLatency << " ms (Acceptable Max: 2s)\n";
}
```

---

## 6. Acceptance Criteria Summary

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    BENCHMARK ACCEPTANCE CRITERIA                           │
│                    EDR AI Agent v1.0                                       │
├─────────────────────────────┬────────────────┬───────────┬────────────────┤
│ Metric                      │ Target         │ Warn Zone │ Fail Zone      │
├─────────────────────────────┼────────────────┼───────────┼────────────────┤
│ PERFORMANCE                 │                │           │                │
│ CPU Average (idle)          │ < 2%           │ 2-5%      │ > 5%           │
│ CPU Average (normal load)   │ < 5%           │ 5-10%     │ > 10%          │
│ CPU Peak (detection event)  │ < 15%          │ 15-25%    │ > 25%          │
│ RAM Working Set             │ < 100 MB       │ 100-150MB │ > 150 MB       │
│ Disk Write (average)        │ < 5 MB/s       │ 5-10 MB/s │ > 10 MB/s      │
│ Agent Startup Time          │ < 3 sec        │ 3-5 sec   │ > 5 sec        │
├─────────────────────────────┼────────────────┼───────────┼────────────────┤
│ INFERENCE                   │                │           │                │
│ Inference Latency P50       │ < 10 ms        │ 10-30 ms  │ > 30 ms        │
│ Inference Latency P99       │ < 50 ms        │ 50-100 ms │ > 100 ms       │
│ Event Throughput            │ > 1,000/sec    │ 500-1K/s  │ < 500/sec      │
│ Alert End-to-End Latency    │ < 500 ms       │ 500ms-1s  │ > 1 sec        │
├─────────────────────────────┼────────────────┼───────────┼────────────────┤
│ DETECTION                   │                │           │                │
│ Overall Detection Rate      │ > 85%          │ 75-85%    │ < 75%          │
│ P0 Critical Detection Rate  │ 100%           │ N/A       │ < 100%         │
│ MITRE Technique Coverage    │ >= 25/29       │ 20-24     │ < 20           │
├─────────────────────────────┼────────────────┼───────────┼────────────────┤
│ ACCURACY                    │                │           │                │
│ False Positive Rate         │ < 5%           │ 5-10%     │ > 10%          │
│ HIGH/CRIT FP (4h benign)    │ 0              │ 1-2       │ > 2            │
│ Alert Rate (benign)         │ < 5/hour       │ 5-10/hr   │ > 10/hour      │
├─────────────────────────────┼────────────────┼───────────┼────────────────┤
│ MODEL                       │                │           │                │
│ Model Size (INT8 ONNX)      │ < 5 MB         │ 5-10 MB   │ > 10 MB        │
│ Model F1-Score              │ > 0.90         │ 0.85-0.90 │ < 0.85         │
│ Quantization Accuracy Drop  │ < 2%           │ 2-5%      │ > 5%           │
└─────────────────────────────┴────────────────┴───────────┴────────────────┘
```

---

## 7. Benchmark Report Template

```markdown
# EDR Agent Benchmark Report
**Date**: YYYY-MM-DD  
**Agent Version**: X.X.X  
**Model Version**: YYYYMMDD_XXXXXX  
**Test Environment**: Windows 10 22H2, 4GB RAM, 2 vCPU

## Performance Results
| Metric            | Measured | Target | Status |
|-------------------|----------|--------|--------|
| CPU Average       | X.X%     | < 5%   | ✅/❌   |
| RAM Peak          | XXX MB   | < 100  | ✅/❌   |
| Inference P99     | XX ms    | < 50ms | ✅/❌   |
| Event Throughput  | XXXX/s   | > 1000 | ✅/❌   |

## Detection Results
| Metric              | Measured | Target | Status |
|---------------------|----------|--------|--------|
| Overall Detection   | XX/29    | >= 25  | ✅/❌   |
| P0 Detection        | XX/15    | 15/15  | ✅/❌   |
| False Positive Rate | X.X%     | < 5%   | ✅/❌   |

## Missed Techniques (if any)
- T1XXX.XXX — [Reason for miss] — [Mitigation plan]

## Regression vs Previous Version
| Metric  | v0.X | v0.Y | Delta |
|---------|------|------|-------|
| CPU     | X%   | X%   | +/-X% |
| F1      | X.XX | X.XX | +/-X  |
```

---

## 8. Automated Benchmark CI Script

```makefile
# Makefile — chạy toàn bộ benchmark suite bằng C++

.PHONY: build benchmark benchmark-perf benchmark-detect benchmark-stress

build:
	mkdir -p build && cd build && cmake .. && make -j4

benchmark: benchmark-perf benchmark-detect
	@echo "=== ALL BENCHMARKS COMPLETE ==="

benchmark-perf:
    @echo "Running performance benchmarks..."
	./build/tests/benchmark/inference_benchmark
	./build/tests/benchmark/ringbuffer_throughput
    powershell -File tests/benchmark/measure_cpu.ps1 -DurationSeconds 60

benchmark-detect:
    @echo "Running detection benchmarks..."
    powershell -ExecutionPolicy Bypass -File tests/atomic_red_team/run_detection_tests.ps1 \
        -WaitSecondsAfterTest 15

benchmark-stress:
    @echo "Running stress benchmarks..."
	./build/tests/benchmark/event_flood_stability
    powershell -File tests/benchmark/ransomware_burst_test.ps1 -FileCount 200

benchmark-fp:
    @echo "Running false positive benchmark (4 hours)..."
    powershell -File tests/benchmark/false_positive_test.ps1 -DurationHours 4

benchmark-all: build benchmark benchmark-stress benchmark-fp
	@echo "=== FULL BENCHMARK SUITE COMPLETE ==="
```
