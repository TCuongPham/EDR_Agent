# d:\Universe\VCS\EDR_AI_Agent\ml\src\augment_credential.py
import sqlite3
import json
import os
import shutil

src_db = r'D:\Universe\VCS\EDR_AI_Agent\build\agent\Release\telemetry_events.db'
dst_db = r'D:\Universe\VCS\EDR_AI_Agent\ml\data\raw\credential_events.db'

print('[*] Buoc 1: Sao chep co so du lieu telemetry moi nhat...')
try:
    os.makedirs(os.path.dirname(dst_db), exist_ok=True)
    shutil.copy2(src_db, dst_db)
    print(f'[+] Da sao chep tu: {src_db} -> {dst_db}')
except Exception as e:
    print(f'[ERROR] Khong the sao chep file: {e}')
    exit(1)

print('[*] Buoc 2: Dang ket noi de tang cuong dac trung trong database moi...')
conn = sqlite3.connect(dst_db)
cursor = conn.cursor()

# Doc tat ca cac dong du lieu de phan tich va sua doi
cursor.execute('SELECT rowid, processName, commandLine, features FROM telemetry_events;')
rows = cursor.fetchall()

updated_lsass = 0
updated_registry = 0

for row in rows:
    rowid, proc_name, cmd_line, feats_str = row
    if not feats_str:
        continue
    
    proc_name_lower = proc_name.lower()
    feats = json.loads(feats_str)
    
    if len(feats) == 25:
        modified = False
        
        # 1. Inject lsass_access & access_rights_vm_read cho tien trinh dump gia lap
        if 'comsvcs_dump' in proc_name_lower or 'pd_dump' in proc_name_lower:
            feats[21] = 1.0  # lsass_access
            feats[22] = 1.0  # access_rights_vm_read
            modified = True
            updated_lsass += 1
            
        # 2. Inject reg_sam_security_access cho tat ca tien trinh reg.exe gia lap ghi registry HKLM\SECURITY
        if 'reg.exe' in proc_name_lower:
            feats[24] = 1.0  # reg_sam_security_access
            modified = True
            updated_registry += 1
            
        if modified:
            new_feats_str = json.dumps(feats)
            cursor.execute('UPDATE telemetry_events SET features = ? WHERE rowid = ?;', (new_feats_str, rowid))

conn.commit()
conn.close()

print(f'\n[+] Quyen quy trinh hoan tat!')
print(f' - Da inject dac trung LSASS (Index 21, 22) cho {updated_lsass} dong du lieu.')
print(f' - Da inject dac trung Registry (Index 24) cho {updated_registry} dong du lieu.')
print(f'[*] File credential_events.db hien da san sang tai: {dst_db}')
