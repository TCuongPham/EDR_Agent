# d:\Universe\VCS\EDR_AI_Agent\ml\src\run_detection_benchmark.py
import sqlite3
import json
import os
import re
import numpy as np

# 1. Load model ONNX dang su dung tu config cua Agent
model_path = r'D:\Universe\VCS\EDR_AI_Agent\ml\data\models_v2\edr_model_v2.onnx'

try:
    import onnxruntime as ort
    session = ort.InferenceSession(model_path)
    print(f'[+] Loaded ONNX model from: {model_path}')
except ImportError:
    print('[Error] Vui long cai dat onnxruntime: pip install onnxruntime numpy')
    exit(1)
except Exception as e:
    print(f'[Error] Khong the load model ONNX: {e}')
    exit(1)

# 2. Logic Tai Hien Tang 1: Rule Engine C++ (Whitelist + Regex)
whitelist = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "taskhostw.exe", "searchindexer.exe"
}

cmdline_regexes = [
    re.compile(r"-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/=]{100,}", re.IGNORECASE),
    re.compile(r"-[Ee]xecution[Pp]olicy\s+[Bb]ypass", re.IGNORECASE),
    re.compile(r"(Invoke-WebRequest|IWR|WebClient|DownloadString|DownloadFile|curl|wget)", re.IGNORECASE),
    re.compile(r"(procdump|minidump|lsass)", re.IGNORECASE)
]

def evaluate_rules(proc_name, proc_path, cmd_line, event_type, fields):
    proc_name_lower = proc_name.lower().split('\\')[-1].split('/')[-1]
    path_lower = proc_path.lower().replace('/', '\\')
    
    is_whitelisted = False
    if proc_name_lower == "system":
        is_whitelisted = True
    elif proc_name_lower == "explorer.exe":
        if path_lower.endswith("\\windows\\explorer.exe"):
            is_whitelisted = True
    elif proc_name_lower in whitelist:
        expected_suffix = "\\windows\\system32\\" + proc_name_lower
        if path_lower.endswith(expected_suffix):
            is_whitelisted = True
            
    if is_whitelisted:
        # Truong hop dac biet: Whitelist doc lap LSASS
        if event_type == "ProcessAccess" and "targetName" in fields:
            target = str(fields["targetName"]).lower()
            if "lsass" in target:
                return "CRITICAL"
        return "CLEAN"
        
    for pattern in cmdline_regexes:
        if pattern.search(cmd_line):
            return "CRITICAL"
            
    return "UNKNOWN"

# 3. Logic Tai Hien Tang 3: Scorer (Hybrid Scoring & Graph Penalty)
def calculate_final_score(ml_score, rule_decision):
    if rule_decision == "CLEAN":
        return 0.0
        
    pattern_match = False
    graph_score = 0.0
    
    if rule_decision == "CRITICAL":
        graph_score = 1.0
        pattern_match = True
        
    base = ml_score
    if pattern_match:
        base += 0.2
        
    suspicious_count = 0
    if graph_score > 0.5:
        suspicious_count += 1
    if ml_score > 0.4:
        suspicious_count += 1
    if pattern_match:
        suspicious_count += 1
        
    if suspicious_count >= 2:
        base *= 1.3
        
    return min(max(base, 0.0), 1.0)

# 4. Ket noi telemetry DB (malware_events.db)
db_path = r'D:\Universe\VCS\EDR_AI_Agent\ml\data\raw\malware_events.db'
if not os.path.exists(db_path):
    print(f'[Error] Khong tim thay database tai: {db_path}')
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute('SELECT processName, commandLine, features, eventType, fields, processPath FROM telemetry_events;')
rows = cursor.fetchall()
conn.close()

print('==================================================')
print('     EDR 3-TIER ENGINE ACCURACY BENCHMARK         ')
print('        (Kich ban kiem thu: simulate.ps1)         ')
print('==================================================')
print(f'Tong so su kien ghi nhan trong DB: {len(rows)}\n')

techniques = {
    'T1547.001 (Registry Run Key Persistence)': {'total': 0, 'ml_det': 0, 'final_det': 0},
    'T1059.001 (PowerShell Download Cradle)': {'total': 0, 'ml_det': 0, 'final_det': 0},
    'T1027 (Obfuscated CommandLine - Base64)': {'total': 0, 'ml_det': 0, 'final_det': 0},
    'T1036.005 (Process Masquerading in Temp)': {'total': 0, 'ml_det': 0, 'final_det': 0},
    'T1053.005 (Scheduled Task Creation)': {'total': 0, 'ml_det': 0, 'final_det': 0},
    'T1543.003 (Windows Service Creation)': {'total': 0, 'ml_det': 0, 'final_det': 0},
    'T1490 (Shadow Copy Deletion / vssadmin)': {'total': 0, 'ml_det': 0, 'final_det': 0}
}

benign_total = 0
benign_ml_fp = 0
benign_final_fp = 0

input_name = session.get_inputs()[0].name

for row in rows:
    proc_name = row[0].lower() if row[0] else ""
    cmd_line = row[1].lower() if row[1] else ""
    feats_str = row[2]
    event_type = row[3] if row[3] else ""
    fields_str = row[4]
    proc_path = row[5] if row[5] else ""
    
    if not feats_str:
        continue
        
    # Evaluate Tier-1 (Rules)
    fields = json.loads(fields_str) if fields_str else {}
    rule_decision = evaluate_rules(proc_name, proc_path, cmd_line, event_type, fields)
    
    # Evaluate Tier-2 (ML Inference)
    try:
        feats = json.loads(feats_str)
        if len(feats) == 25:
            mapping_25_to_16 = [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 15, 16, 17, 18, 20]
            feats = [feats[i] for i in mapping_25_to_16]
            
        if len(feats) != 16:
            continue
            
        input_data = np.array([feats], dtype=np.float32)
        outputs = session.run(None, {input_name: input_data})
        probs = outputs[1][0]
        ml_score = float(probs[1])
        
        # Recalculate Tier-3 (Final Scorer logic)
        final_score = calculate_final_score(ml_score, rule_decision)
        
    except Exception:
        continue
    
    # Kiem tra thuoc kich ban nao
    matched_tech = None
    if 'reg.exe' in proc_name:
        matched_tech = 'T1547.001 (Registry Run Key Persistence)'
    elif 'powershell' in proc_name and ('iwr' in cmd_line or 'downloadstring' in cmd_line or 'downloadfile' in cmd_line):
        matched_tech = 'T1059.001 (PowerShell Download Cradle)'
    elif 'powershell' in proc_name and (' -enc' in cmd_line or ' /enc' in cmd_line or ' -e ' in cmd_line or ' -encoded' in cmd_line):
        matched_tech = 'T1027 (Obfuscated CommandLine - Base64)'
    elif 'whoami_temp' in proc_name:
        matched_tech = 'T1036.005 (Process Masquerading in Temp)'
    elif 'schtasks.exe' in proc_name:
        matched_tech = 'T1053.005 (Scheduled Task Creation)'
    elif 'sc.exe' in proc_name:
        matched_tech = 'T1543.003 (Windows Service Creation)'
    elif 'vssadmin' in cmd_line or 'shadowcopy' in cmd_line:
        matched_tech = 'T1490 (Shadow Copy Deletion / vssadmin)'
        
    if matched_tech:
        techniques[matched_tech]['total'] += 1
        if ml_score >= 0.5:
            techniques[matched_tech]['ml_det'] += 1
        if final_score >= 0.5:
            techniques[matched_tech]['final_det'] += 1
    else:
        # Hanh vi Benign
        if 'powershell' not in proc_name and 'cmd.exe' not in proc_name:
            benign_total += 1
            if ml_score >= 0.5:
                benign_ml_fp += 1
            if final_score >= 0.5:
                benign_final_fp += 1

# In bang so sanh
print(f'{"MITRE ATT&CK Technique":<42} | {"Total":<5} | {"ML Detect":<9} | {"Final (3-Tier)":<14} | {"ML Rate":<7} | {"Final Rate":<10}')
print('-' * 98)

total_mal = 0
det_ml = 0
det_final = 0

for name, stats in techniques.items():
    t = stats['total']
    ml = stats['ml_det']
    fn = stats['final_det']
    ml_rate = f'{ml/t*100:.1f}%' if t > 0 else '0.0%'
    fn_rate = f'{fn/t*100:.1f}%' if t > 0 else '0.0%'
    print(f'{name:<42} | {t:<5} | {ml:<9} | {fn:<14} | {ml_rate:<7} | {fn_rate:<10}')
    
    if t > 0:
        total_mal += t
        det_ml += ml
        det_final += fn

# Tong ket cac chi so
print('==================================================================================')
print('                               SUMMARY STATISTICS                                 ')
print('==================================================================================')
print(f'1. True Positive Rate (ML Engine Only) : {det_ml}/{total_mal} ({det_ml/total_mal*100:.2f}%)')
print(f'2. True Positive Rate (Full 3-Tiers)   : {det_final}/{total_mal} ({det_final/total_mal*100:.2f}%)')
print('----------------------------------------------------------------------------------')
print(f'3. False Positive Rate (ML Engine Only): {benign_ml_fp}/{benign_total} ({benign_ml_fp/benign_total*100:.2f}%)')
print(f'4. False Positive Rate (Full 3-Tiers)  : {benign_final_fp}/{benign_total} ({benign_final_fp/benign_total*100:.2f}%)')
print('==================================================================================')
