# D:\Universe\VCS\EDR_AI_Agent\simulate.ps1
# Script gia lap thu thap Telemetry NHAN 1: Malware Behavior
# Chay bang: powershell.exe -ExecutionPolicy Bypass -File .\simulate.ps1

$logFile = "C:\windows\temp\simulation_debug.log"
"--- BAT DAU GIA LAP MALWARE ---" | Out-File $logFile

function Log-Step($msg) {
    $time = Get-Date -Format "HH:mm:ss"
    $formatted = "[$time] $msg"
    Write-Host $formatted -ForegroundColor Yellow
    $formatted | Out-File $logFile -Append
}

try {
    for ($i = 1; $i -le 150; $i++) {
        Log-Step "=== Vong lap $i/150 ==="

        # 1. Registry Run Key
        Log-Step "Chay kich ban 1: Registry Run Key..."
        reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "MalwareRunKey_$i" /t REG_SZ /d "C:\windows\temp\fake_$i.exe" /f > $null 2>&1
        reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "MalwareRunKey_$i" /f > $null 2>&1
        Log-Step "Hoan thanh kich ban 1."
        Start-Sleep -Milliseconds 100 # Tre giua cac buoc

        # 2. Download Cradle
        Log-Step "Chay kich ban 2: Download Cradle..."
        Start-Process powershell.exe -ArgumentList "-NoProfile -NonInteractive -Command `"iwr -Uri http://127.0.0.1:9999/payload_$i.ps1`"" -Wait -WindowStyle Hidden > $null 2>&1
        Log-Step "Hoan thanh kich ban 2."
        Start-Sleep -Milliseconds 150 # PowerShell nang hon nen nghi lau hon chut

        # 3. Encoded Base64 Command
        Log-Step "Chay kich ban 3: Encoded Base64..."
        $bytes   = [System.Text.Encoding]::Unicode.GetBytes("Write-Host 'Simulation $i'")
        $encoded = [Convert]::ToBase64String($bytes)
        Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -enc $encoded" -Wait > $null 2>&1
        Log-Step "Hoan thanh kich ban 3."
        Start-Sleep -Milliseconds 150

        # 4. Temp Path Execution
        Log-Step "Chay kich ban 4: Temp Path Exec..."
        $tempExe = "C:\windows\temp\whoami_temp_$i.exe"
        copy C:\windows\system32\whoami.exe $tempExe > $null 2>&1
        & $tempExe > $null 2>&1
        Start-Sleep -Milliseconds 50
        if (Test-Path $tempExe) { Remove-Item $tempExe -Force > $null 2>&1 }
        Log-Step "Hoan thanh kich ban 4."
        Start-Sleep -Milliseconds 100

        # 5. Scheduled Task
        Log-Step "Chay kich ban 5: Scheduled Task..."
        schtasks.exe /create /tn "MalwareTask_$i" /tr "cmd.exe /c echo $i" /sc daily /st 12:00 /f > $null 2>&1
        schtasks.exe /delete /tn "MalwareTask_$i" /f > $null 2>&1
        Log-Step "Hoan thanh kich ban 5."
        Start-Sleep -Milliseconds 100

        # 6. Service Creation
        Log-Step "Chay kich ban 6: Service Creation..."
        sc.exe create "MalwareService_$i" binpath= "C:\windows\temp\service_$i.exe" start= demand > $null 2>&1
        sc.exe delete "MalwareService_$i" > $null 2>&1
        Log-Step "Hoan thanh kich ban 6."
        Start-Sleep -Milliseconds 100

        # 7. Suspicious Keywords (vssadmin)
        Log-Step "Chay kich ban 7: Suspicious Keywords..."
        cmd.exe /c "echo bypass noprofile vssadmin shadowcopy rundll32 certutil" > $null 2>&1
        Log-Step "Hoan thanh kich ban 7."

        # Randomize delay tong cuoi vong lap de telemetry tu nhien
        $randomDelay = Get-Random -Minimum 200 -Maximum 600
        Start-Sleep -Milliseconds $randomDelay
    }
} catch {
    Log-Step "LOI PHAT SINH: $_"
}

Log-Step "--- HOAN THANH GIA LAP MALWARE ---"
