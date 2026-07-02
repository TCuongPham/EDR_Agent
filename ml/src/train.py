# ml/src/train.py
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

def load_db_features(path):
    """Reads a SQLite database and extracts the 25-dimensional feature vectors."""
    records = []
    if not os.path.exists(path):
        print(f"[Warning] File {path} not found. Skipping.")
        return records
    
    try:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        # Check if table exists
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
                if isinstance(features, list):
                    if len(features) == 25:
                        records.append(features)
                    else:
                        print(f"[Warning] Record {row_idx} in {path} has invalid features size: expected 25, got {len(features)}")
            except Exception:
                continue
        conn.close()
    except Exception as e:
        print(f"[Error] Failed to read from {path}: {e}")
    return records

def main():
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/raw"))
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/models"))
    os.makedirs(models_dir, exist_ok=True)
    
    print("====================================================")
    # 1. Load datasets
    print("[1] Loading raw events logs from SQLite databases...")
    benign_path = os.path.join(data_dir, "benign_events.db")
    malware_path = os.path.join(data_dir, "malware_events.db")
    cred_path = os.path.join(data_dir, "credential_events.db")
    
    X_benign = load_db_features(benign_path)
    X_malware = load_db_features(malware_path)
    X_cred = load_db_features(cred_path)
    
    print(f"    - Benign samples (Label 0): {len(X_benign)}")
    print(f"    - Malware samples (Label 1): {len(X_malware)}")
    print(f"    - Credential Access samples (Label 2): {len(X_cred)}")
    
    X_raw = X_benign + X_malware + X_cred
    y_raw = [0]*len(X_benign) + [1]*len(X_malware) + [2]*len(X_cred)
    
    if len(X_raw) == 0:
        print("\n[!] ERROR: No valid training events found. Please make sure to collect telemetry first and store logs in:")
        print(f"    {benign_path}")
        print(f"    {malware_path}")
        print(f"    {cred_path}")
        return

    X = np.array(X_raw, dtype=np.float32)
    y = np.array(y_raw, dtype=np.int32)
    
    # 2. Split dataset
    print("[2] Splitting dataset (70% Train, 15% Val, 15% Test)...")
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )
    
    # 3. Train Random Forest Baseline
    print("[3] Training Random Forest Baseline...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"    - Random Forest Test Accuracy: {rf_acc:.4f}")
    print("    - Random Forest Classification Report:")
    print(classification_report(y_test, rf_preds, target_names=["Benign", "Malware", "Credential"]))
    
    # Save RF model
    joblib.dump(rf_model, os.path.join(models_dir, "rf_baseline.pkl"))

    # 4. Tune LightGBM using Optuna
    print("[4] Tuning LightGBM hyperparameters with Optuna...")
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    
    def objective(trial):
        params = {
            'objective': 'multiclass',
            'num_class': 3,
            'metric': 'multi_logloss',
            'boosting_type': 'gbdt',
            'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.2),
            'num_leaves': trial.suggest_int('num_leaves', 15, 127),
            'max_depth': trial.suggest_int('max_depth', 3, 10),
            'min_child_samples': trial.suggest_int('min_child_samples', 5, 50),
            'feature_fraction': trial.suggest_float('feature_fraction', 0.6, 1.0),
            'bagging_fraction': trial.suggest_float('bagging_fraction', 0.6, 1.0),
            'bagging_freq': trial.suggest_int('bagging_freq', 1, 7),
            'verbose': -1,
            'random_state': 42
        }
        
        train_ds = lgb.Dataset(X_train, label=y_train)
        val_ds = lgb.Dataset(X_val, label=y_val, reference=train_ds)
        
        # Train model with early stopping
        model = lgb.train(
            params,
            train_ds,
            num_boost_round=150,
            valid_sets=[val_ds],
            callbacks=[lgb.early_stopping(stopping_rounds=15, verbose=False)]
        )
        
        preds = model.predict(X_val)
        pred_labels = np.argmax(preds, axis=1)
        return accuracy_score(y_val, pred_labels)

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=25)
    print("    - Best Trial Accuracy:", study.best_value)
    print("    - Best Hyperparameters:")
    for k, v in study.best_params.items():
        print(f"      {k}: {v}")

    # 5. Train final LightGBM model using best parameters
    print("[5] Training final LightGBM model with best parameters...")
    best_params = study.best_params
    best_params['objective'] = 'multiclass'
    best_params['num_class'] = 3
    best_params['metric'] = 'multi_logloss'
    best_params['verbose'] = -1
    best_params['random_state'] = 42
    
    train_ds = lgb.Dataset(X_train, label=y_train)
    val_ds = lgb.Dataset(X_val, label=y_val, reference=train_ds)
    
    best_lgb = lgb.train(
        best_params,
        train_ds,
        num_boost_round=300,
        valid_sets=[val_ds],
        callbacks=[lgb.early_stopping(stopping_rounds=20)]
    )
    
    # 6. Evaluate final LightGBM model on Test set
    print("[6] Evaluating LightGBM on Test set...")
    lgb_preds = best_lgb.predict(X_test)
    lgb_pred_labels = np.argmax(lgb_preds, axis=1)
    lgb_acc = accuracy_score(y_test, lgb_pred_labels)
    
    # Calculate Multiclass ROC-AUC
    try:
        roc_auc = roc_auc_score(y_test, lgb_preds, multi_class='ovr')
        print(f"    - LightGBM Test Accuracy: {lgb_acc:.4f} (ROC-AUC: {roc_auc:.4f})")
    except Exception:
        print(f"    - LightGBM Test Accuracy: {lgb_acc:.4f}")
        
    print("    - LightGBM Classification Report:")
    print(classification_report(y_test, lgb_pred_labels, target_names=["Benign", "Malware", "Credential"]))
    
    # Save model using both text format (for onnxmltools) and joblib
    lgb_model_path = os.path.join(models_dir, "best_lgb_model.txt")
    best_lgb.save_model(lgb_model_path)
    joblib.dump(best_lgb, os.path.join(models_dir, "best_lgb_model.pkl"))
    print(f"[Done] Saved final LightGBM model to {lgb_model_path}")
    print("====================================================")

if __name__ == "__main__":
    main()
