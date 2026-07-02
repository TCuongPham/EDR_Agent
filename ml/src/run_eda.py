# ml/src/run_eda.py
import os
import json
import sqlite3
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier

# Cấu hình giao diện seaborn
sns.set_theme(style="whitegrid")

# Danh sách 25 tên đặc trưng theo đúng chỉ số index từ agent C++
FEATURE_NAMES = [
    "child_spawn_count_5s",
    "child_spawn_count_30s",
    "child_spawn_count_300s",
    "cmdline_length",
    "cmdline_entropy",
    "has_encoded_cmdline",
    "has_download_cradle",
    "cmdline_suspicious_kw_count",
    "is_lolbin",
    "parent_is_lolbin",
    "token_elevated",
    "process_depth_in_tree",
    "parent_is_office",
    "parent_is_browser",
    "parent_is_script_engine",
    "is_in_temp_path",
    "is_in_system_path",
    "lifetime_ms_log",
    "unusual_parent_child",
    "process_rarity_score",
    "tree_fan_out_max",
    "lsass_access",
    "access_rights_vm_read",
    "persistence_key_access",
    "reg_sam_security_access"
]

def load_features(db_path, label):
    """
    Kết nối tới cơ sở dữ liệu SQLite và trích xuất các vector đặc trưng 25 chiều.
    """
    if not os.path.exists(db_path):
        print(f"[Cảnh báo] Không tìm thấy file {db_path}.")
        return pd.DataFrame()
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT features FROM telemetry_events;")
        rows = cursor.fetchall()
    except sqlite3.OperationalError as e:
        print(f"[Lỗi] Không tìm thấy bảng trong {db_path}: {e}")
        conn.close()
        return pd.DataFrame()
        
    records = []
    for row in rows:
        feats_str = row[0]
        if not feats_str:
            continue
        try:
            feats = json.loads(feats_str)
            if len(feats) == 25:
                records.append(feats)
        except Exception:
            continue
            
    conn.close()
    df = pd.DataFrame(records, columns=FEATURE_NAMES)
    df["label"] = label
    return df

def main():
    src_dir = os.path.dirname(__file__)
    data_dir = os.path.abspath(os.path.join(src_dir, "../data/raw"))
    output_dir = os.path.abspath(os.path.join(src_dir, "../data/eda"))
    os.makedirs(output_dir, exist_ok=True)
    
    print("====================================================")
    print("[*] Running Feature EDA and generating plots...")
    
    # 1. Tải tập dữ liệu
    df_benign = load_features(os.path.join(data_dir, "benign_events.db"), label=0)
    df_malware = load_features(os.path.join(data_dir, "malware_events.db"), label=1)
    df_cred = load_features(os.path.join(data_dir, "credential_events.db"), label=2)
    
    if len(df_benign) == 0 and len(df_malware) == 0 and len(df_cred) == 0:
        print("[Error] No data loaded. Check database files.")
        return
        
    df = pd.concat([df_benign, df_malware, df_cred], ignore_index=True)
    class_map = {0: "Benign (Lành tính)", 1: "Malware (Mã độc)", 2: "Credential Access (Chiếm quyền)"}
    df["class_name"] = df["label"].map(class_map)
    
    print(f"    - Loaded Benign: {len(df_benign)} samples")
    print(f"    - Loaded Malware: {len(df_malware)} samples")
    print(f"    - Loaded Credential Access: {len(df_cred)} samples")
    
    # 2. Vẽ biểu đồ các đặc trưng chỉ thị hành vi chiếm quyền (Credential Access)
    print("[*] Generating Credential Access feature comparison plot...")
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    sns.barplot(data=df, x="class_name", y="lsass_access", ax=axes[0], hue="class_name", legend=False, palette="viridis")
    axes[0].set_title("Tần suất lsass_access theo loại nhãn")
    axes[0].set_ylabel("Giá trị đặc trưng trung bình (0.0 - 1.0)")
    axes[0].set_xlabel("Loại sự kiện")
    
    sns.barplot(data=df, x="class_name", y="access_rights_vm_read", ax=axes[1], hue="class_name", legend=False, palette="viridis")
    axes[1].set_title("Tần suất access_rights_vm_read theo loại nhãn")
    axes[1].set_ylabel("Giá trị đặc trưng trung bình (0.0 - 1.0)")
    axes[1].set_xlabel("Loại sự kiện")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "eda_credential_access.png"), dpi=150)
    plt.close()
    
    # 3. Vẽ biểu đồ các đặc trưng chỉ thị mã độc (Malware Indicators)
    print("[*] Generating Malware feature comparison plot...")
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    sns.barplot(data=df, x="class_name", y="has_encoded_cmdline", ax=axes[0], hue="class_name", legend=False, palette="magma")
    axes[0].set_title("Cờ dòng lệnh mã hóa (has_encoded_cmdline)")
    axes[0].set_ylabel("Tỷ lệ xuất hiện")
    axes[0].set_xlabel("Loại sự kiện")
    
    sns.barplot(data=df, x="class_name", y="cmdline_suspicious_kw_count", ax=axes[1], hue="class_name", legend=False, palette="magma")
    axes[1].set_title("Số từ khóa nghi vấn (cmdline_suspicious_kw_count)")
    axes[1].set_ylabel("Giá trị trung bình")
    axes[1].set_xlabel("Loại sự kiện")
    
    sns.barplot(data=df, x="class_name", y="has_download_cradle", ax=axes[2], hue="class_name", legend=False, palette="magma")
    axes[2].set_title("Cờ lệnh tải file (has_download_cradle)")
    axes[2].set_ylabel("Tỷ lệ xuất hiện")
    axes[2].set_xlabel("Loại sự kiện")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "eda_malware.png"), dpi=150)
    plt.close()

    # 4. Vẽ biểu đồ đường dẫn chạy file và độ hiếm của tiến trình
    print("[*] Generating path and rarity comparison plot...")
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    sns.barplot(data=df, x="class_name", y="is_in_temp_path", ax=axes[0], hue="class_name", legend=False, palette="coolwarm")
    axes[0].set_title("Chạy từ thư mục tạm (is_in_temp_path)")
    axes[0].set_ylabel("Tỷ lệ xuất hiện")
    axes[0].set_xlabel("Loại sự kiện")
    
    sns.barplot(data=df, x="class_name", y="process_rarity_score", ax=axes[1], hue="class_name", legend=False, palette="coolwarm")
    axes[1].set_title("Điểm độ hiếm tiến trình (process_rarity_score)")
    axes[1].set_ylabel("Điểm trung bình (càng cao càng hiếm)")
    axes[1].set_xlabel("Loại sự kiện")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "eda_paths.png"), dpi=150)
    plt.close()

    # 5. Vẽ ma trận tương quan Heatmap (Không che/mask để hiển thị đầy đủ hàng và cột)
    print("[*] Generating full feature correlation matrix heatmap...")
    plt.figure(figsize=(15, 13))
    corr = df[FEATURE_NAMES].corr()
    
    # Vẽ heatmap đầy đủ để tránh làm trống hàng đầu tiên của child_spawn_count_5s
    sns.heatmap(corr, cmap="coolwarm", annot=False, fmt=".2f", linewidths=.5)
    plt.title("Ma trận tương quan đặc trưng (Feature Correlation Matrix - Full)")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "eda_correlation.png"), dpi=150)
    plt.close()

    # 6. Huấn luyện Random Forest để lấy mức độ quan trọng đặc trưng (Feature Importance)
    print("[*] Training Random Forest and plotting feature importance...")
    X = df[FEATURE_NAMES].values
    y = df["label"].values
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X, y)
    
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    imp_df = pd.DataFrame({
        "Feature": [FEATURE_NAMES[i] for i in indices],
        "Importance": importances[indices]
    })
    
    plt.figure(figsize=(10, 8))
    sns.barplot(data=imp_df, x="Importance", y="Feature", hue="Feature", legend=False, palette="viridis")
    plt.title("Mức độ quan trọng đặc trưng (Random Forest Feature Importance)")
    plt.xlabel("Chỉ số Gini Importance")
    plt.ylabel("Đặc trưng")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "eda_feature_importance.png"), dpi=150)
    plt.close()

    # 7. Ghi tóm tắt kết quả phân tích ra file JSON
    summary_path = os.path.join(output_dir, "eda_summary.json")
    means_dict = df.groupby("class_name")[FEATURE_NAMES].mean().to_dict()
    
    summary = {
        "class_counts": {
            "Benign": len(df_benign),
            "Malware": len(df_malware),
            "Credential Access": len(df_cred)
        },
        "feature_means": means_dict,
        "feature_importances": imp_df.to_dict(orient="records")
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
        
    print(f"[Done] Saved all plots and summary files in: {output_dir}")
    print("====================================================")

if __name__ == "__main__":
    main()
