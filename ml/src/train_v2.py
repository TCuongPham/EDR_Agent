# ml/src/train_v2.py
# ============================================================
# Phiên bản huấn luyện thứ 2 (Feature-Selected, Binary)
# Phân loại nhị phân: Benign (0) vs Malware (1)
# Sử dụng 16/25 đặc trưng sau khi loại bỏ các đặc trưng
# không có ích theo kết quả EDA, và các đặc trưng đặc thù
# Credential Dumping (đã loại bỏ class này):
#   - child_spawn_count_5s     (index 0)  -> tương quan 0.93 với _30s
#   - child_spawn_count_300s   (index 2)  -> tương quan 0.88 với _30s
#   - parent_is_office         (index 12) -> Gini 0.004%, thiếu kịch bản
#   - parent_is_browser        (index 13) -> Gini 0.5%, thiếu kịch bản
#   - process_rarity_score     (index 19) -> logic nghịch lý (benign > malware)
#   - persistence_key_access   (index 23) -> hằng số = 0, std = 0
#   - lsass_access             (index 21) -> đặc thù Credential Dumping, đã loại class
#   - access_rights_vm_read    (index 22) -> đặc thù Credential Dumping, đã loại class
#   - reg_sam_security_access  (index 24) -> đặc thù Credential Dumping, đã loại class
# ============================================================

import os
import json
import sqlite3
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
import lightgbm as lgb
import optuna
import joblib

# ============================================================
# Định nghĩa 25 tên đặc trưng gốc (theo thứ tự index trong DB)
# ============================================================
ALL_FEATURE_NAMES = [
    "child_spawn_count_5s",        # index 0  ❌ loại
    "child_spawn_count_30s",       # index 1  ✅ giữ
    "child_spawn_count_300s",      # index 2  ❌ loại
    "cmdline_length",              # index 3  ✅ giữ
    "cmdline_entropy",             # index 4  ✅ giữ
    "has_encoded_cmdline",         # index 5  ✅ giữ
    "has_download_cradle",         # index 6  ✅ giữ
    "cmdline_suspicious_kw_count", # index 7  ✅ giữ
    "is_lolbin",                   # index 8  ✅ giữ
    "parent_is_lolbin",            # index 9  ✅ giữ
    "token_elevated",              # index 10 ✅ giữ
    "process_depth_in_tree",       # index 11 ✅ giữ
    "parent_is_office",            # index 12 ❌ loại
    "parent_is_browser",           # index 13 ❌ loại
    "parent_is_script_engine",     # index 14 ✅ giữ
    "is_in_temp_path",             # index 15 ✅ giữ
    "is_in_system_path",           # index 16 ✅ giữ
    "lifetime_ms_log",             # index 17 ✅ giữ
    "unusual_parent_child",        # index 18 ✅ giữ
    "process_rarity_score",        # index 19 ❌ loại
    "tree_fan_out_max",            # index 20 ✅ giữ
    "lsass_access",                # index 21 ✅ giữ
    "access_rights_vm_read",       # index 22 ✅ giữ
    "persistence_key_access",      # index 23 ❌ loại
    "reg_sam_security_access",     # index 24 ✅ giữ
]

# Tập các đặc trưng bị loại bỏ dựa theo kết quả EDA
# và loại bỏ Credential class (3 đặc trưng cuối)
DROPPED_FEATURES = {
    "child_spawn_count_5s",
    "child_spawn_count_300s",
    "parent_is_office",
    "parent_is_browser",
    "process_rarity_score",
    "persistence_key_access",
    # Credential-specific features — loại bỏ cùng với Credential class
    "lsass_access",
    "access_rights_vm_read",
    "reg_sam_security_access",
}

# Tập đặc trưng được giữ lại (19 đặc trưng)
SELECTED_FEATURES = [f for f in ALL_FEATURE_NAMES if f not in DROPPED_FEATURES]

# Chỉ số của các đặc trưng được chọn trong vector 25 chiều gốc
SELECTED_INDICES = [i for i, f in enumerate(ALL_FEATURE_NAMES) if f not in DROPPED_FEATURES]


def load_db_features(path):
    """
    Đọc database SQLite và trích xuất vector đặc trưng 25 chiều.
    Chỉ trả về 19 chiều được chọn (theo SELECTED_INDICES).
    """
    records = []
    if not os.path.exists(path):
        print(f"[Warning] File {path} not found. Skipping.")
        return records

    try:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='telemetry_events';")
        if not cursor.fetchone():
            print(f"[Warning] Table 'telemetry_events' not found in {path}. Skipping.")
            conn.close()
            return records

        cursor.execute("SELECT features FROM telemetry_events;")
        rows = cursor.fetchall()

        for row_idx, row in enumerate(rows, 1):
            features_str = row[0]
            if not features_str:
                continue
            try:
                features = json.loads(features_str)
                if isinstance(features, list) and len(features) == 25:
                    # Lọc chỉ lấy 19 đặc trưng theo chỉ số đã chọn
                    selected = [features[i] for i in SELECTED_INDICES]
                    records.append(selected)
                elif isinstance(features, list):
                    print(f"[Warning] Record {row_idx} in {path}: expected 25 features, got {len(features)}")
            except Exception:
                continue

        conn.close()
    except Exception as e:
        print(f"[Error] Failed to read {path}: {e}")

    return records


def main():
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/raw"))
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/models_v2"))
    os.makedirs(models_dir, exist_ok=True)

    n_features = len(SELECTED_FEATURES)

    print("====================================================")
    print(f" EDR AI Agent - Training v2 ({n_features}/25 features selected)")
    print("====================================================")
    print(f"\n[Config] Removed features ({len(DROPPED_FEATURES)}):")
    for f in DROPPED_FEATURES:
        print(f"    - {f}")
    print(f"\n[Config] Selected features ({n_features}):")
    for i, f in enumerate(SELECTED_FEATURES):
        print(f"    [{i:2d}] {f}")

    # --------------------------------------------------------
    # 1. Tải dữ liệu từ 2 database SQLite (Binary: Benign vs Malware)
    #    Credential class đã được loại bỏ khỏi pipeline
    # --------------------------------------------------------
    print("\n[1] Loading raw events from SQLite databases (Binary mode)...")
    benign_path  = os.path.join(data_dir, "benign_events.db")
    malware_path = os.path.join(data_dir, "malware_events.db")

    X_benign  = load_db_features(benign_path)
    X_malware = load_db_features(malware_path)

    print(f"    - Benign samples  (Label 0): {len(X_benign)}")
    print(f"    - Malware samples (Label 1): {len(X_malware)}")

    X_raw = X_benign + X_malware
    y_raw = [0]*len(X_benign) + [1]*len(X_malware)

    if len(X_raw) == 0:
        print("\n[!] ERROR: No valid training data found.")
        return

    X = np.array(X_raw, dtype=np.float32)
    y = np.array(y_raw, dtype=np.int32)
    print(f"\n    Total: {len(X)} samples | Feature shape: {X.shape}")

    # --------------------------------------------------------
    # 2. Chia tập dữ liệu (70% train / 15% val / 15% test)
    # --------------------------------------------------------
    print("\n[2] Splitting dataset (70% Train | 15% Val | 15% Test)...")
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )
    print(f"    - Train : {len(X_train)} samples")
    print(f"    - Val   : {len(X_val)}   samples")
    print(f"    - Test  : {len(X_test)}  samples")

    # --------------------------------------------------------
    # 3. Huấn luyện Random Forest Baseline
    # --------------------------------------------------------
    print("\n[3] Training Random Forest Baseline...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    rf_acc   = accuracy_score(y_test, rf_preds)

    print(f"    - Random Forest Test Accuracy: {rf_acc:.4f}")
    print("    - Classification Report:")
    print(classification_report(
        y_test, rf_preds,
        target_names=["Benign", "Malware"]
    ))

    # Lưu RF model
    joblib.dump(rf_model, os.path.join(models_dir, "rf_baseline_v2.pkl"))

    # --------------------------------------------------------
    # 4. Tối ưu siêu tham số LightGBM bằng Optuna (25 trials)
    # --------------------------------------------------------
    print("[4] Tuning LightGBM hyperparameters with Optuna (25 trials)...")
    optuna.logging.set_verbosity(optuna.logging.WARNING)

    def objective(trial):
        params = {
            'objective':         'binary',
            'metric':            'binary_logloss',
            'boosting_type':     'gbdt',
            'learning_rate':     trial.suggest_float('learning_rate', 0.01, 0.2),
            'num_leaves':        trial.suggest_int('num_leaves', 15, 127),
            'max_depth':         trial.suggest_int('max_depth', 3, 10),
            'min_child_samples': trial.suggest_int('min_child_samples', 5, 50),
            'feature_fraction':  trial.suggest_float('feature_fraction', 0.6, 1.0),
            'bagging_fraction':  trial.suggest_float('bagging_fraction', 0.6, 1.0),
            'bagging_freq':      trial.suggest_int('bagging_freq', 1, 7),
            'verbose':           -1,
            'random_state':      42,
        }

        train_ds = lgb.Dataset(X_train, label=y_train)
        val_ds   = lgb.Dataset(X_val, label=y_val, reference=train_ds)

        model = lgb.train(
            params, train_ds,
            num_boost_round=150,
            valid_sets=[val_ds],
            callbacks=[lgb.early_stopping(stopping_rounds=15, verbose=False)]
        )

        # Binary: predict trả về xác suất lớp 1 (Malware), ngưỡng 0.5
        preds       = model.predict(X_val)
        pred_labels = (preds >= 0.5).astype(int)
        return accuracy_score(y_val, pred_labels)

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=25)

    print(f"    - Best Validation Accuracy : {study.best_value:.4f}")
    print("    - Best Hyperparameters:")
    for k, v in study.best_params.items():
        print(f"      {k}: {v}")

    # --------------------------------------------------------
    # 5. Huấn luyện mô hình LightGBM cuối cùng
    # --------------------------------------------------------
    print("\n[5] Training final LightGBM with best parameters...")
    best_params = study.best_params.copy()
    best_params.update({
        'objective':    'binary',
        'metric':       'binary_logloss',
        'verbose':      -1,
        'random_state': 42,
    })

    train_ds = lgb.Dataset(X_train, label=y_train)
    val_ds   = lgb.Dataset(X_val,   label=y_val, reference=train_ds)

    best_lgb = lgb.train(
        best_params, train_ds,
        num_boost_round=300,
        valid_sets=[val_ds],
        callbacks=[lgb.early_stopping(stopping_rounds=20)]
    )

    # --------------------------------------------------------
    # 6. Đánh giá mô hình LightGBM cuối cùng trên tập Test
    # --------------------------------------------------------
    print("\n[6] Evaluating final LightGBM on Test set...")
    # Binary: predict trả về xác suất lớp 1 (Malware), ngưỡng 0.5
    lgb_preds       = best_lgb.predict(X_test)
    lgb_pred_labels = (lgb_preds >= 0.5).astype(int)
    lgb_acc         = accuracy_score(y_test, lgb_pred_labels)

    try:
        roc_auc = roc_auc_score(y_test, lgb_preds)
        print(f"    - LightGBM Test Accuracy : {lgb_acc:.4f}  (ROC-AUC: {roc_auc:.4f})")
    except Exception:
        print(f"    - LightGBM Test Accuracy : {lgb_acc:.4f}")

    print("    - Classification Report:")
    print(classification_report(
        y_test, lgb_pred_labels,
        target_names=["Benign", "Malware"]
    ))

    # --------------------------------------------------------
    # 7. Lưu kết quả và metadata đặc trưng
    # --------------------------------------------------------
    lgb_txt_path = os.path.join(models_dir, "best_lgb_model_v2.txt")
    lgb_pkl_path = os.path.join(models_dir, "best_lgb_model_v2.pkl")
    best_lgb.save_model(lgb_txt_path)
    joblib.dump(best_lgb, lgb_pkl_path)

    # Lưu metadata đặc trưng để export_onnx_v2.py dùng đúng số chiều
    meta = {
        "version": "v2",
        "n_features": n_features,
        "feature_names": SELECTED_FEATURES,
        "selected_indices_from_original_25": SELECTED_INDICES,
        "dropped_features": list(DROPPED_FEATURES),
        "lgbm_best_accuracy_val": study.best_value,
        "lgbm_test_accuracy": float(lgb_acc),
        "rf_test_accuracy": float(rf_acc),
    }
    meta_path = os.path.join(models_dir, "feature_meta_v2.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"\n[Done] Models and metadata saved to: {models_dir}")
    print(f"    - {os.path.basename(lgb_txt_path)}")
    print(f"    - {os.path.basename(lgb_pkl_path)}")
    print(f"    - rf_baseline_v2.pkl")
    print(f"    - feature_meta_v2.json")
    print("====================================================")


if __name__ == "__main__":
    main()
