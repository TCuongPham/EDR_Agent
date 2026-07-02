# D:\Universe\VCS\EDR_AI_Agent\simulate1.ps1
# Script gia lap Credential Access - Phien ban toi uu hoa dac trung Registry & Tranh chu ky Defender
# Chay bang: powershell.exe -ExecutionPolicy Bypass -File .\simulate1.ps1

$logFile = "C:\windows\temp\simulate1_debug.log"
"--- BAT DAU GIA LAP CREDENTIAL ACCESS ---" | Out-File $logFile

function Log-Step($msg) {
    $time = Get-Date -Format "HH:mm:ss"
    $formatted = "[$time] $msg"
    Write-Host $formatted -ForegroundColor Cyan
    $formatted | Out-File $logFile -Append
}

# Cac tu khoa can thiet
$kw_lsa     = "lsass"
$kw_mimi    = "mimikatz"
$kw_sekurl  = "sekurlsa"
$kw_proc    = "procdump"
$kw_secret  = "secretsdump"

try {
    for ($i = 1; $i -le 150; $i++) {
        Log-Step "=== Vong lap $i/150 ==="

        # =========================================================
        # KICH BAN 1: LSASS Dump Simulation
        # Kich hoat: is_in_temp_path, cmdline_suspicious_kw_count (lsass, comsvcs)
        # =========================================================
        try {
            Log-Step "Chay kich ban 1: LSASS Dump Simulation..."
            $spoofExe = "C:\windows\temp\comsvcs_dump_$i.exe"
            copy C:\windows\system32\whoami.exe $spoofExe > $null 2>&1
            if (Test-Path $spoofExe) {
                Start-Process $spoofExe -ArgumentList "minidump $kw_lsa" -WindowStyle Hidden -Wait -ErrorAction Stop > $null
                Remove-Item $spoofExe -Force > $null 2>&1
            }
            Log-Step "Hoan thanh kich ban 1."
        } catch {
            Log-Step "[LOI KICH BAN 1] Bo qua: $_"
        }
        Start-Sleep -Milliseconds 100

        # =========================================================
        # KICH BAN 2: Registry SECURITY Access (T1003.002)
        # Kich hoat: reg_sam_security_access (1.0 - Do thuc hien ghi vao HKLM\SECURITY)
        # Yeu cau: Chay duoi quyen SYSTEM de co quyen ghi vao SECURITY hive.
        # =========================================================
        try {
            Log-Step "Chay kich ban 2: Registry SECURITY Access..."
            # Thuc hien ghi key thu nghiem de tao su kien RegistryCreate/RegistrySet
            $p1 = Start-Process reg.exe -ArgumentList "add HKLM\SECURITY\EDR_Test_$i /f" -PassThru -WindowStyle Hidden -ErrorAction Stop
            $p1.WaitForExit(1500) > $null
            
            # Xoa key sau khi ghi de don dep
            $p2 = Start-Process reg.exe -ArgumentList "delete HKLM\SECURITY\EDR_Test_$i /f" -PassThru -WindowStyle Hidden -ErrorAction Stop
            $p2.WaitForExit(1500) > $null
            
            Log-Step "Hoan thanh kich ban 2 (Registry Write)."
        } catch {
            Log-Step "[LOI KICH BAN 2] Bo qua (Can chay shell SYSTEM bang PsExec de ghi SECURITY): $_"
        }
        Start-Sleep -Milliseconds 100

        # =========================================================
        # KICH BAN 3: Mimikatz Process Name Spoofing
        # Kich hoat: cmdline_suspicious_kw_count (mimikatz, sekurlsa)
        # =========================================================
        try {
            Log-Step "Chay kich ban 3: Mimikatz Spoofing..."
            $mimiExe = "C:\windows\temp\${kw_mimi}_$i.exe"
            copy C:\windows\system32\whoami.exe $mimiExe > $null 2>&1
            if (Test-Path $mimiExe) {
                Start-Process $mimiExe -ArgumentList "$kw_sekurl logonpasswords" -WindowStyle Hidden -Wait -ErrorAction Stop > $null
                Remove-Item $mimiExe -Force > $null 2>&1
            }
            Log-Step "Hoan thanh kich ban 3."
        } catch {
            Log-Step "[LOI KICH BAN 3] Bo qua: $_"
        }
        Start-Sleep -Milliseconds 100

        # =========================================================
        # KICH BAN 4: Procdump Process Name Spoofing (Tranh chu ky ten file procdump.exe)
        # Kich hoat: cmdline_suspicious_kw_count (procdump, lsass)
        # =========================================================
        try {
            Log-Step "Chay kich ban 4: Procdump Spoofing..."
            $procExe = "C:\windows\temp\pd_dump_$i.exe"
            copy C:\windows\system32\whoami.exe $procExe > $null 2>&1
            if (Test-Path $procExe) {
                # Truyen tu khoa procdump va lsass vao arguments de EDR ghi nhan
                Start-Process $procExe -ArgumentList "$kw_proc $kw_lsa" -WindowStyle Hidden -Wait -ErrorAction Stop > $null
                Remove-Item $procExe -Force > $null 2>&1
            }
            Log-Step "Hoan thanh kich ban 4."
        } catch {
            Log-Step "[LOI KICH BAN 4] Bo qua: $_"
        }
        Start-Sleep -Milliseconds 100

        # =========================================================
        # KICH BAN 5: Credential File Harvesting
        # =========================================================
        try {
            Log-Step "Chay kich ban 5: Credential harvesting..."
            $credExe = "C:\windows\temp\cred_harvest_$i.exe"
            copy C:\windows\system32\whoami.exe $credExe > $null 2>&1
            if (Test-Path $credExe) {
                Start-Process $credExe -ArgumentList "/upn" -WindowStyle Hidden -Wait -ErrorAction Stop > $null
                Remove-Item $credExe -Force > $null 2>&1
            }
            Log-Step "Hoan thanh kich ban 5."
        } catch {
            Log-Step "[LOI KICH BAN 5] Bo qua: $_"
        }
        Start-Sleep -Milliseconds 100

        # =========================================================
        # KICH BAN 6: Secretsdump Process Name Spoofing
        # =========================================================
        try {
            Log-Step "Chay kich ban 6: Secretsdump Spoofing..."
            $secExe = "C:\windows\temp\${kw_secret}_$i.exe"
            copy C:\windows\system32\whoami.exe $secExe > $null 2>&1
            if (Test-Path $secExe) {
                Start-Process $secExe -ArgumentList "ntds.dit local" -WindowStyle Hidden -Wait -ErrorAction Stop > $null
                Remove-Item $secExe -Force > $null 2>&1
            }
            Log-Step "Hoan thanh kich ban 6."
        } catch {
            Log-Step "[LOI KICH BAN 6] Bo qua: $_"
        }

        $randomDelay = Get-Random -Minimum 200 -Maximum 500
        Start-Sleep -Milliseconds $randomDelay
    }
} catch {
    Log-Step "LOI PHAT SINH: $_"
}

Log-Step "--- HOAN THANH GIA LAP CREDENTIAL ACCESS ---"
