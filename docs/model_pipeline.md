# Model Pipeline — EDR AI Agent
## Quy trình Huấn luyện, Tối ưu hóa & Đóng gói Model AI

> **Phiên bản**: v1.0 | **Ngày**: 2026-06-07  
> **Mục đích**: Mô tả chi tiết pipeline từ raw data → production ONNX model

---

## 1. Tổng quan Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: DATA COLLECTION & LABELING                                │
│  ETW Trace Logs (Benign) + Atomic Red Team (Malicious)              │
│  → Labeled JSON/Parquet events (0=Benign, 1=Malware, 2=Credential)  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 2: FEATURE EXTRACTION (Offline)                              │
│  Python Feature Pipeline → training_dataset.parquet                │
│  32 CORE features + N EXTENDED features × N samples                 │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 3: EXPLORATORY DATA ANALYSIS                                 │
│  Class distribution, Feature importance, Correlation matrix         │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 4: MODEL TRAINING & SELECTION                                │
│  LightGBM Multiclass (Main) / Random Forest (Baseline)               │
│  → Best model selected by F1-score + inference speed               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 5: HYPERPARAMETER OPTIMIZATION                               │
│  Optuna (Bayesian optimization) — 100 trials                        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 6: MODEL EXPORT → ONNX & CONFIG                              │
│  • skl2onnx / onnxmltools → edr_model.onnx                          │
│  • export_features_config.py → features_config.json                 │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 7: QUANTIZATION (INT8)                                       │
│  onnxruntime.quantization → edr_model_int8.onnx                    │
│  ~4x size reduction, ~2x inference speedup                         │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 8: VALIDATION & DEPLOYMENT                                   │
│  Output diff test (FP32 vs INT8), Latency benchmark                 │
│  → Deploy to agent: edr_model_int8.onnx + features_config.json      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dataset Preparation

### 2.1 Data Collection Script

```python
# ml/src/data_collection.py

import subprocess
import json
import time
import shutil
from pathlib import Path
from datetime import datetime

class DatasetCollector:
    """
    Thu thập ETW events thô (.etl) trong khi chạy các kịch bản Atomic Red Team.
    Sử dụng logman để điều khiển Session và lưu tệp kết quả.
    """
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.current_label = 0  # 0=benign, 1=suspicious, 2=malicious
        self.current_technique = "baseline"
        self.session_name = "EDR_Telemetry_Session"
        self.etl_path = r"C:\EDR\telemetry.etl"
        
    def start_etw_session(self):
        """Khởi tạo phiên ghi log ETW thông qua logman"""
        # Stop session cũ nếu còn kẹt
        subprocess.run(["logman", "stop", self.session_name], capture_output=True)
        
        # Tạo session ghi ra file telemetry.etl
        subprocess.run([
            "logman", "create", "trace", self.session_name,
            "-ow", "-o", self.etl_path
        ], check=True)
        
        # Đăng ký các Providers
        providers = [
            ("{22c607dd-8a81-40c0-b57e-dc0d05931d74}", "0x70", "4"), # Kernel-Process (Start/Stop/Image)
            ("{edd08927-c37b-4de1-ad0f-51892c3c1272}", "0x10", "4"), # Kernel-File
            ("{7dd27088-cc2c-47a2-ba64-db83f9958a3a}", "0x40", "4"), # Kernel-Network
            ("{70eb4f03-c1de-4f73-a051-33d13d5413bd}", "0x1", "4")   # Kernel-Registry
        ]
        
        for guid, keywords, level in providers:
            subprocess.run([
                "logman", "update", "trace", self.session_name,
                "-p", guid, keywords, level
            ], check=True)
            
        # Start session
        subprocess.run(["logman", "start", self.session_name], check=True)
        print("[Collector] ETW Trace Session started.")
        
    def stop_etw_session_and_save(self):
        """Dừng phiên ghi log và lưu trữ file thu được"""
        subprocess.run(["logman", "stop", self.session_name], capture_output=True)
        dest_file = self.output_dir / f"{self.current_technique}_{int(time.time())}.etl"
        if Path(self.etl_path).exists():
            shutil.copy2(self.etl_path, dest_file)
            print(f"[Collector] Copied trace file to: {dest_file}")
        else:
            print("[Collector] Error: Trace file not found.")

    def collect_benign_baseline(self, duration_seconds: int = 3600):
        """Thu thập baseline hoạt động bình thường"""
        print(f"Collecting benign baseline for {duration_seconds}s...")
        self.current_label = 0
        self.current_technique = "benign_baseline"
        
        self.start_etw_session()
        time.sleep(duration_seconds)
        self.stop_etw_session_and_save()
        
    def collect_attack_simulation(self, technique_id: str, test_num: int = 1):
        """Chạy giả lập tấn công Atomic Red Team trong khi chạy ETW trace"""
        self.current_label = 2
        self.current_technique = technique_id
        
        self.start_etw_session()
        time.sleep(5)  # 5s pre-attack window
        
        print(f"Executing Invoke-AtomicTest {technique_id} -TestNumbers {test_num}")
        subprocess.run([
            "powershell.exe", "-Command",
            f"Invoke-AtomicTest {technique_id} -TestNumbers {test_num}"
        ], timeout=120)
        
        time.sleep(30)  # 30s post-attack window for callbacks
        self.stop_etw_session_and_save()


# Danh sách Atomic Red Team tests cho dataset

```python
# Malware Behavior — Class 1
# eids map to: 1=ProcessStart, 5=ImageLoad, 10=TcpIp/Connect, 64=FileCreate
atomic_scenarios_malware = [
    {"technique": "T1059.001", "name": "PowerShell Encoded Command",
     "eids": [1],
     "features": ["has_encoded_cmdline", "cmdline_entropy", "cmdline_length"]},
    {"technique": "T1218.011", "name": "Rundll32 DLL Sideloading",
     "eids": [1, 5],
     "features": ["is_lolbin", "unsigned_dll_from_temp", "image_not_signed"]},
    {"technique": "T1105",     "name": "Certutil Download Cradle",
     "eids": [1, 10, 64],
     "features": ["has_download_cradle", "is_lolbin", "net_outbound_count_30s", "write_dump_or_exec_file"]},
    {"technique": "T1059.001", "name": "Office Macro → PowerShell Chain",
     "eids": [1],
     "features": ["parent_is_office", "has_encoded_cmdline", "process_depth_in_tree"]},
    {"technique": "T1218.010", "name": "Regsvr32 Squiblydoo LOLBin",
     "eids": [1, 10],
     "features": ["is_lolbin", "net_outbound_count_30s", "is_in_temp_path"]},
]

# Credential Access — Class 2
# eids map to: 1=ProcessStart, 5=ImageLoad, 13=OpenProcessHandle, 64=FileCreate, 1=RegistryCreateKey, 5=RegistrySetValueKey
atomic_scenarios_credential = [
    {"technique": "T1003.001", "name": "LSASS Dump via Procdump",
     "eids": [1, 13, 64],
     "features": ["lsass_access", "access_rights_vm_read", "write_dump_or_exec_file", "max_file_entropy_30s"]},
    {"technique": "T1003.001", "name": "LSASS Dump via comsvcs.dll MiniDump",
     "eids": [1, 5, 13, 64],
     "features": ["lsass_access", "is_lolbin", "write_dump_or_exec_file"]},
    {"technique": "T1003.001", "name": "Mimikatz sekurlsa::logonpasswords",
     "eids": [1, 13],
     "features": ["lsass_access", "access_rights_vm_read", "image_not_signed", "cmdline_suspicious_kw_count"]},
    {"technique": "T1003.002", "name": "SAM Registry Dump via reg save",
     "eids": [1, 1, 5, 64],
     "features": ["reg_sam_security_access", "write_dump_or_exec_file", "persistence_key_access"]},
    {"technique": "T1555",     "name": "Token Impersonation / Privilege Abuse",
     "eids": [1, 13],
     "features": ["token_elevated", "lsass_access", "access_rights_vm_read"]},
]
```

### 2.2 Dataset Statistics Targets

```
Mục tiêu dataset tối thiểu:
┌─────────────────────────────────────────────────────────────────┐
│ Class                     │ Samples   │ Nguồn                   │
├─────────────────────────────────────────────────────────────────┤
│ Benign (0)                │ 50,000+   │ Hoạt động thường nhật   │
│ Malware Behavior (1)      │ 20,000+   │ LOLBins, C2, Macros     │
│ Credential Access (2)     │ 15,000+   │ LSASS access, SAM dump  │
├─────────────────────────────────────────────────────────────────┤
│ TOTAL                     │ 85,000+   │                         │
└─────────────────────────────────────────────────────────────────┘

Class imbalance xử lý:
- Sử dụng class_weight='balanced' trong LightGBM training
- SMOTE oversampling cho class minority (nếu cần)
- Stratified K-Fold cross validation để tránh data leakage
```

---

## 3. Exploratory Data Analysis (EDA)

```python
# ml/notebooks/01_eda.ipynb

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_selection import mutual_info_classif

# Load dataset
df = pd.read_parquet('data/processed/training_dataset.parquet')

# 1. Class distribution
print("Class Distribution:")
print(df['label'].value_counts())
# → Đảm bảo không có class quá thiểu (< 10% tổng)

# 2. Feature importance (mutual information)
X = df.drop(['label', 'event_id'], axis=1)
y = df['label']
mi_scores = mutual_info_classif(X, y, random_state=42)
feature_importance = pd.Series(mi_scores, index=X.columns).sort_values(ascending=False)
print("\nTop 15 Most Informative Features:")
print(feature_importance.head(15))

# 3. Correlation matrix (loại bỏ features tương quan cao > 0.95)
corr_matrix = X.corr().abs()
upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
to_drop = [col for col in upper_tri.columns if any(upper_tri[col] > 0.95)]
print(f"\nFeatures to drop (high correlation): {to_drop}")

# 4. Outlier analysis
for col in X.columns:
    q1 = X[col].quantile(0.01)
    q99 = X[col].quantile(0.99)
    outliers = X[(X[col] < q1) | (X[col] > q99)].shape[0]
    if outliers > len(X) * 0.05:  # > 5% outliers
        print(f"High outlier rate in {col}: {outliers/len(X)*100:.1f}%")
```

---

## 4. Model Training

### 4.1 Baseline Models

```python
# ml/src/train.py

import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, f1_score
)
import xgboost as xgb
import lightgbm as lgb
import mlflow
import mlflow.sklearn

# Load & split data
df = pd.read_parquet('data/processed/training_dataset.parquet')
X = df.drop(['label', 'event_id'], axis=1).values.astype(np.float32)
y = df['label'].values

# Stratified K-Fold (5 folds)
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# ─────────────────────────────────────────────
# MODEL 1: Random Forest (Baseline)
# ─────────────────────────────────────────────
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    min_samples_split=5,
    class_weight='balanced',    # Xử lý class imbalance
    n_jobs=-1,                  # Sử dụng tất cả CPU cores
    random_state=42
)

with mlflow.start_run(run_name="RandomForest_baseline"):
    cv_results = cross_validate(
        rf_model, X, y, cv=cv,
        scoring=['f1_weighted', 'roc_auc_ovr', 'precision_weighted', 'recall_weighted'],
        return_train_score=True
    )
    
    mlflow.log_metrics({
        'cv_f1_mean': cv_results['test_f1_weighted'].mean(),
        'cv_f1_std': cv_results['test_f1_weighted'].std(),
        'cv_auc_mean': cv_results['test_roc_auc_ovr'].mean(),
    })
    
    # Final training on full dataset
    rf_model.fit(X, y)
    mlflow.sklearn.log_model(rf_model, "random_forest")
    
    print(f"RF F1 (CV): {cv_results['test_f1_weighted'].mean():.4f} "
          f"± {cv_results['test_f1_weighted'].std():.4f}")


# ─────────────────────────────────────────────
# MODEL 2: XGBoost (Gradient Boosting)
# ─────────────────────────────────────────────
# Tính sample weights để xử lý imbalance
from sklearn.utils.class_weight import compute_sample_weight
sample_weights = compute_sample_weight('balanced', y)

xgb_model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric='mlogloss',
    objective='multi:softprob',
    num_class=3,
    tree_method='hist',         # Nhanh hơn cho tabular data
    n_jobs=-1,
    random_state=42
)

with mlflow.start_run(run_name="XGBoost_baseline"):
    cv_results = cross_validate(
        xgb_model, X, y, cv=cv,
        scoring=['f1_weighted', 'roc_auc_ovr'],
        fit_params={'sample_weight': sample_weights}
    )
    mlflow.log_metrics({
        'cv_f1_mean': cv_results['test_f1_weighted'].mean(),
        'cv_auc_mean': cv_results['test_roc_auc_ovr'].mean(),
    })
    xgb_model.fit(X, y, sample_weight=sample_weights)
    mlflow.sklearn.log_model(xgb_model, "xgboost")


# ─────────────────────────────────────────────
# MODEL 3: LightGBM (Fastest, recommended)
# ─────────────────────────────────────────────
lgb_model = lgb.LGBMClassifier(
    objective='multiclass',
    num_class=3,              # 0=Benign, 1=Malware Behavior, 2=Credential Access
    metric='multi_logloss',
    n_estimators=500,
    learning_rate=0.05,
    num_leaves=63,
    max_depth=-1,
    feature_fraction=0.8,
    bagging_fraction=0.8,
    bagging_freq=5,
    class_weight='balanced',
    n_jobs=-1,
    verbose=-1,
    random_state=42
)

with mlflow.start_run(run_name="LightGBM_baseline"):
    cv_results = cross_validate(
        lgb_model, X, y, cv=cv,
        scoring=['f1_weighted', 'roc_auc_ovr']
    )
    lgb_model.fit(X, y)
    mlflow.sklearn.log_model(lgb_model, "lightgbm")
    
    print(f"LightGBM F1 (CV): {cv_results['test_f1_weighted'].mean():.4f}")
```

### 4.2 Hyperparameter Optimization (Optuna)

```python
# ml/src/optimize.py

import optuna
from sklearn.model_selection import StratifiedKFold
import lightgbm as lgb
import numpy as np

def objective(trial) -> float:
    """
    Optuna objective function cho LightGBM.
    Maximize F1-weighted score.
    """
    params = {
        'n_estimators': trial.suggest_int('n_estimators', 100, 500),
        'max_depth': trial.suggest_int('max_depth', 4, 15),
        'num_leaves': trial.suggest_int('num_leaves', 20, 150),
        'learning_rate': trial.suggest_float('learning_rate', 0.005, 0.1, log=True),
        'subsample': trial.suggest_float('subsample', 0.5, 1.0),
        'colsample_bytree': trial.suggest_float('colsample_bytree', 0.5, 1.0),
        'min_child_samples': trial.suggest_int('min_child_samples', 5, 50),
        'reg_alpha': trial.suggest_float('reg_alpha', 1e-8, 10.0, log=True),
        'reg_lambda': trial.suggest_float('reg_lambda', 1e-8, 10.0, log=True),
        'class_weight': 'balanced',
        'objective': 'multiclass',
        'num_class': 3,
        'n_jobs': -1,
        'verbose': -1,
    }
    
    model = lgb.LGBMClassifier(**params)
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y, cv=cv, scoring='f1_weighted')
    
    return scores.mean()


# Chạy optimization
study = optuna.create_study(
    direction='maximize',
    sampler=optuna.samplers.TPESampler(seed=42),
    pruner=optuna.pruners.MedianPruner(n_warmup_steps=10)
)

study.optimize(objective, n_trials=100, timeout=3600)  # Max 1 giờ

print("Best params:", study.best_params)
print("Best F1:", study.best_value)

# Plot optimization history
fig = optuna.visualization.plot_optimization_history(study)
fig.write_image('reports/optimization_history.png')

fig2 = optuna.visualization.plot_param_importances(study)
fig2.write_image('reports/param_importance.png')
```

---

## 5. Model Evaluation

```python
# ml/src/evaluate.py

import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, average_precision_score,
    RocCurveDisplay, PrecisionRecallDisplay
)

def comprehensive_evaluation(model, X_test, y_test, model_name: str):
    """Đánh giá toàn diện model trên test set"""
    
    # Predictions
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)  # [N, 3]
    
    # 1. Classification Report
    print(f"\n{'='*60}")
    print(f"Model: {model_name}")
    print(classification_report(y_test, y_pred, 
                                target_names=['Benign', 'Malware Behavior', 'Credential Access']))
    
    # 2. Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(cm)
    
    # 3. AUC-ROC (one-vs-rest)
    auc = roc_auc_score(y_test, y_proba, multi_class='ovr', average='weighted')
    print(f"AUC-ROC (weighted): {auc:.4f}")
    
    # 4. False Positive Rate (quan trọng nhất với security)
    # FP = Benign bị classify sai là Malicious/Suspicious
    benign_mask = y_test == 0
    fp_rate = np.mean(y_pred[benign_mask] != 0)  # Benign classified as non-benign
    print(f"False Positive Rate (Benign misclassified): {fp_rate:.4f} ({fp_rate*100:.2f}%)")
    
    # 5. False Negative Rate (detection miss rate)
    malicious_mask = y_test == 2
    fn_rate = np.mean(y_pred[malicious_mask] != 2)  # Malicious missed
    print(f"False Negative Rate (Malicious missed): {fn_rate:.4f} ({fn_rate*100:.2f}%)")
    
    # Target metrics:
    assert fp_rate < 0.05, f"FP rate {fp_rate:.3f} exceeds target 5%!"
    assert fn_rate < 0.15, f"FN rate {fn_rate:.3f} exceeds target 15%!"
    
    return {
        'model': model_name,
        'f1_weighted': f1_score(y_test, y_pred, average='weighted'),
        'auc_roc': auc,
        'fp_rate': fp_rate,
        'fn_rate': fn_rate,
    }
```

---

## 6. Export sang ONNX

### 6.1 Random Forest → ONNX

```python
# ml/src/export_onnx.py

from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx
import onnxruntime as ort
import numpy as np

def export_sklearn_to_onnx(
    sklearn_model,
    model_name: str,
    n_features: int = 64,
    output_path: str = None
) -> str:
    """Export scikit-learn model sang ONNX format"""
    
    # Định nghĩa input type: batch_size × n_features float32
    initial_type = [('float_input', FloatTensorType([None, n_features]))]
    
    # Convert
    onnx_model = convert_sklearn(
        sklearn_model,
        initial_types=initial_type,
        target_opset=17,        # ONNX opset version
        options={
            'zipmap': False,    # Tắt zipmap để output là tensor thay vì dict
        }
    )
    
    # Validate ONNX model
    onnx.checker.check_model(onnx_model)
    
    # Save
    if output_path is None:
        output_path = f'data/models/{model_name}.onnx'
    
    with open(output_path, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    
    print(f"Exported ONNX model to: {output_path}")
    
    # Verify output matches sklearn
    _verify_onnx_model(sklearn_model, onnx_model, n_features)
    
    return output_path


def _verify_onnx_model(sklearn_model, onnx_model, n_features: int):
    """Đảm bảo output ONNX == output sklearn trong tolerance"""
    
    # Tạo random test data
    np.random.seed(42)
    X_test = np.random.rand(100, n_features).astype(np.float32)
    
    # Sklearn prediction
    sklearn_proba = sklearn_model.predict_proba(X_test)
    
    # ONNX Runtime prediction
    sess = ort.InferenceSession(onnx_model.SerializeToString())
    input_name = sess.get_inputs()[0].name
    ort_outputs = sess.run(None, {input_name: X_test})
    onnx_proba = ort_outputs[1]  # [N, 3] probabilities
    
    # Compare
    max_diff = np.max(np.abs(sklearn_proba - onnx_proba))
    print(f"Max difference sklearn vs ONNX: {max_diff:.2e}")
    
    assert max_diff < 1e-4, f"ONNX output differs too much from sklearn: {max_diff}"
    print("✓ ONNX verification passed!")


# Export XGBoost
def export_xgboost_to_onnx(xgb_model, n_features: int = 64):
    """XGBoost native ONNX export"""
    import onnxmltools
    from onnxconverter_common import FloatTensorType
    
    initial_type = [('float_input', FloatTensorType([None, n_features]))]
    onnx_model = onnxmltools.convert_xgboost(
        xgb_model,
        initial_types=initial_type,
        target_opset=17
    )
    
    output_path = 'data/models/xgboost_edr.onnx'
    with open(output_path, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    
    return output_path
```

---

## 7. Quantization (INT8)

```python
# ml/src/quantize.py

import onnx
from onnxruntime.quantization import (
    quantize_dynamic,
    quantize_static,
    QuantType,
    QuantizationMode,
    CalibrationMethod,
    CalibrationDataReader
)
import numpy as np
import time

class CalibrationReader(CalibrationDataReader):
    """
    Cung cấp calibration data cho static quantization.
    Static quantization chính xác hơn dynamic nhưng cần calibration data.
    """
    
    def __init__(self, calibration_data: np.ndarray, batch_size: int = 32):
        self.data = calibration_data
        self.batch_size = batch_size
        self.current_idx = 0
    
    def get_next(self):
        if self.current_idx >= len(self.data):
            return None
        
        batch = self.data[self.current_idx:self.current_idx + self.batch_size]
        self.current_idx += self.batch_size
        
        return {'float_input': batch.astype(np.float32)}


def quantize_model(
    input_model_path: str,
    output_model_path: str,
    calibration_data: np.ndarray,
    method: str = 'dynamic'  # 'dynamic' hoặc 'static'
) -> dict:
    """
    Quantize ONNX model sang INT8.
    
    Dynamic Quantization:
    - Nhanh hơn để implement
    - Không cần calibration data
    - Phù hợp cho tree-based models (RF, XGBoost)
    - ~2-3x size reduction
    
    Static Quantization:
    - Chính xác hơn cho neural networks
    - Cần calibration data (~100-1000 representative samples)
    - ~4x size reduction, ~2x inference speedup
    """
    
    # Đo size trước quantization
    import os
    original_size = os.path.getsize(input_model_path)
    
    if method == 'dynamic':
        quantize_dynamic(
            model_input=input_model_path,
            model_output=output_model_path,
            weight_type=QuantType.QUInt8,    # Unsigned INT8 cho weights
            optimize_model=True
        )
    
    elif method == 'static':
        calibration_reader = CalibrationReader(calibration_data)
        
        quantize_static(
            model_input=input_model_path,
            model_output=output_model_path,
            calibration_data_reader=calibration_reader,
            weight_type=QuantType.QUInt8,
            activation_type=QuantType.QUInt8,
            calibrate_method=CalibrationMethod.MinMax,
            quant_format=QuantizationMode.IntegerOps
        )
    
    # Đo size sau quantization
    quantized_size = os.path.getsize(output_model_path)
    compression_ratio = original_size / quantized_size
    
    # Benchmark inference latency
    latency_fp32 = _benchmark_latency(input_model_path)
    latency_int8 = _benchmark_latency(output_model_path)
    
    # Validate accuracy không bị drop quá nhiều
    accuracy_drop = _validate_accuracy_drop(
        input_model_path, output_model_path, calibration_data
    )
    
    results = {
        'original_size_kb': original_size / 1024,
        'quantized_size_kb': quantized_size / 1024,
        'compression_ratio': compression_ratio,
        'latency_fp32_ms': latency_fp32,
        'latency_int8_ms': latency_int8,
        'speedup': latency_fp32 / latency_int8,
        'accuracy_drop': accuracy_drop,
    }
    
    print(f"\nQuantization Results ({method}):")
    print(f"  Size: {original_size/1024:.1f}KB → {quantized_size/1024:.1f}KB "
          f"(ratio: {compression_ratio:.2f}x)")
    print(f"  Latency: {latency_fp32:.2f}ms → {latency_int8:.2f}ms "
          f"(speedup: {latency_fp32/latency_int8:.2f}x)")
    print(f"  Accuracy drop: {accuracy_drop:.4f}")
    
    # Hard requirement
    assert accuracy_drop < 0.02, f"Accuracy drop {accuracy_drop:.4f} exceeds 2% threshold!"
    
    return results


def _benchmark_latency(model_path: str, n_runs: int = 1000) -> float:
    """Đo latency trung bình (milliseconds) cho single inference"""
    import onnxruntime as ort
    
    sess = ort.InferenceSession(
        model_path,
        providers=['CPUExecutionProvider']
    )
    input_name = sess.get_inputs()[0].name
    
    # Warmup
    dummy_input = np.random.rand(1, 64).astype(np.float32)
    for _ in range(50):
        sess.run(None, {input_name: dummy_input})
    
    # Benchmark
    start = time.perf_counter()
    for _ in range(n_runs):
        sess.run(None, {input_name: dummy_input})
    end = time.perf_counter()
    
    avg_ms = (end - start) / n_runs * 1000
    return avg_ms


def _validate_accuracy_drop(fp32_path: str, int8_path: str, X_test: np.ndarray) -> float:
    """Tính mức độ sụt giảm accuracy sau quantization"""
    import onnxruntime as ort
    
    sess_fp32 = ort.InferenceSession(fp32_path)
    sess_int8 = ort.InferenceSession(int8_path)
    
    input_name = sess_fp32.get_inputs()[0].name
    X = X_test.astype(np.float32)
    
    labels_fp32 = sess_fp32.run(None, {input_name: X})[0]
    labels_int8 = sess_int8.run(None, {input_name: X})[0]
    
    disagreement_rate = np.mean(labels_fp32 != labels_int8)
    return float(disagreement_rate)
```

---

## 8. Tích hợp trực tiếp ONNX Runtime C++ API (cho C++ Agent)

Trong kiến trúc thuần C++, chúng ta tích hợp trực tiếp thư viện **ONNX Runtime C++ API** (header `<onnxruntime_cxx_api.h>`) vào Agent Daemon mà không cần lớp cgo bridge trung gian. Dưới đây là lớp Wrapper C++ thực hiện nạp mô hình và suy luận.

```cpp
// agent/src/inference/onnx_inferencer.cpp
#include <onnxruntime_cxx_api.h>
#include <vector>
#include <string>
#include <memory>
#include <iostream>

class ONNXInferencer {
private:
    Ort::Env m_env;
    Ort::Session m_session = nullptr;
    std::vector<const char*> m_inputNames;
    std::vector<const char*> m_outputNames;
    std::vector<int64_t> m_inputShape;

public:
    ONNXInferencer(const std::wstring& modelPath) 
        : m_env(ORT_LOGGING_LEVEL_WARNING, "EDRAgent") {
        
        Ort::SessionOptions sessionOptions;
        sessionOptions.SetIntraOpNumThreads(1); // EDR Agent chạy đơn luồng để tránh chiếm dụng CPU máy trạm
        sessionOptions.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        
        // Tắt Memory Pattern để tối ưu hóa việc phân bổ bộ nhớ cho các sự kiện đơn lẻ
        sessionOptions.DisableMemPattern();

        // Nạp session
        m_session = Ort::Session(m_env, modelPath.c_str(), sessionOptions);

        m_inputNames = { "float_input" };
        m_outputNames = { "output_label", "output_probability" };
        m_inputShape = { 1, 64 }; // Batch size 1, 64 features
    }

    // Thực hiện suy luận (Inference) trên 64 chiều đặc trưng
    // Trả về threat_score trong khoảng [0.0, 1.0]
    float Infer(const std::vector<float>& features) {
        if (features.size() != 64) return 0.0f;

        Ort::MemoryInfo memoryInfo = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        
        // Tạo input tensor từ vector đặc trưng (không copy dữ liệu)
        Ort::Value inputTensor = Ort::Value::CreateTensor<float>(
            memoryInfo, 
            const_cast<float*>(features.data()), 
            features.size(), 
            m_inputShape.data(), 
            m_inputShape.size()
        );

        // Chạy suy luận qua Ort Session
        auto outputTensors = m_session.Run(
            Ort::RunOptions{nullptr}, 
            m_inputNames.data(), &inputTensor, 1, 
            m_outputNames.data(), m_outputNames.size()
        );

        // Lấy dữ liệu xác suất đầu ra
        float* probabilities = outputTensors[1].GetTensorMutableData<float>();
        
        // Tính điểm đe dọa tổng hợp:
        // probabilities[0] = Benign, probabilities[1] = Suspicious, probabilities[2] = Malicious
        float threatScore = probabilities[1] * 0.5f + probabilities[2] * 1.0f;
        
        if (threatScore > 1.0f) threatScore = 1.0f;
        if (threatScore < 0.0f) threatScore = 0.0f;
        
        return threatScore;
    }
};
```

---

## 9. Model Versioning & Deployment

```python
# ml/src/model_registry.py

import hashlib
import json
from pathlib import Path
from datetime import datetime

class ModelRegistry:
    """
    Quản lý phiên bản model đơn giản bằng file system.
    (Thay thế MLflow model registry cho môi trường embedded)
    """
    
    REGISTRY_FILE = 'data/models/registry.json'
    
    def register(
        self,
        model_path: str,
        metrics: dict,
        description: str = ""
    ) -> str:
        """Đăng ký model mới vào registry"""
        
        # Tính checksum
        with open(model_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()[:16]
        
        version = f"v{datetime.now().strftime('%Y%m%d_%H%M')}_{sha256}"
        
        entry = {
            'version': version,
            'path': str(model_path),
            'registered_at': datetime.now().isoformat(),
            'sha256': sha256,
            'metrics': metrics,
            'description': description,
            'is_production': False
        }
        
        # Load existing registry
        registry = self._load_registry()
        registry['models'].append(entry)
        
        # Save
        with open(self.REGISTRY_FILE, 'w') as f:
            json.dump(registry, f, indent=2)
        
        print(f"Registered model {version}")
        return version
    
    def promote_to_production(self, version: str):
        """Đánh dấu model là production-ready"""
        registry = self._load_registry()
        
        for model in registry['models']:
            model['is_production'] = (model['version'] == version)
        
        with open(self.REGISTRY_FILE, 'w') as f:
            json.dump(registry, f, indent=2)
        
        print(f"Promoted {version} to production")
    
    def get_production_model(self) -> dict:
        """Lấy thông tin model đang active"""
        registry = self._load_registry()
        production = [m for m in registry['models'] if m['is_production']]
        return production[-1] if production else None


# Deployment script
def deploy_model_to_agent(model_path: str, agent_models_dir: str = '../agent/models/'):
    """Copy model mới vào agent directory"""
    import shutil
    
    dest = Path(agent_models_dir) / 'edr_model_int8.onnx'
    dest_backup = Path(agent_models_dir) / 'edr_model_int8.onnx.bak'
    
    # Backup current model
    if dest.exists():
        shutil.copy2(dest, dest_backup)
    
    # Deploy new model
    shutil.copy2(model_path, dest)
    print(f"Deployed {model_path} → {dest}")
    print("Agent sẽ reload model ở lần restart tiếp theo")
    print("Hoặc gửi SIGHUP để hot-reload (nếu agent hỗ trợ)")
```

---

## 10. Export features_config.json sau Training

Sau khi huấn luyện mô hình, script tự động sinh ra file `features_config.json` để Agent dùng khi load mô hình.

```python
# ml/src/export_features_config.py
import json
import lightgbm as lgb
from datetime import datetime

def export_features_config(model: lgb.Booster, feature_names: list[str],
                            feature_meta: dict, output_path: str):
    """
    Export features_config.json đi kèm file .onnx.
    
    Args:
        model: LightGBM Booster đã train
        feature_names: Danh sách tên đặc trưng theo thứ tự đầu vào mô hình
        feature_meta: Dict chứa metadata: {name: {type, default, namespace}}
        output_path: Đường dẫn lưu file JSON
    """
    config = {
        "model_name": f"edr_lgbm_multiclass_{datetime.now().strftime('%Y%m%d')}",
        "feature_count": len(feature_names),
        "classes": {
            "0": "Benign",
            "1": "Malware Behavior",
            "2": "Credential Access"
        },
        "generated_at": datetime.now().isoformat(),
        "features": []
    }
    
    for idx, name in enumerate(feature_names):
        meta = feature_meta.get(name, {})
        config["features"].append({
            "index":     idx,
            "name":      name,
            "type":      meta.get("type", "float"),
            "default":   meta.get("default", 0.0),
            "namespace": meta.get("namespace", "process")
        })
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"[OK] Exported features_config.json: {len(feature_names)} features → {output_path}")


# Ví dụ sử dụng sau training:
if __name__ == "__main__":
    # Giả sử model đã được train
    feature_meta = {
        "child_spawn_count_5s":     {"type": "count",  "default": 0.0,  "namespace": "process"},
        "lsass_access":             {"type": "binary", "default": 0.0,  "namespace": "memory"},
        "beacon_score":             {"type": "float",  "default": -1.0, "namespace": "network"},
        "max_file_entropy_30s":     {"type": "float",  "default": -1.0, "namespace": "file"},
        "persistence_key_access":   {"type": "binary", "default": 0.0,  "namespace": "registry"},
        "unsigned_dll_from_temp":   {"type": "binary", "default": 0.0,  "namespace": "dll"},
        # ... thêm tất cả 32 features
    }
    export_features_config(
        model=model,
        feature_names=model.feature_name(),
        feature_meta=feature_meta,
        output_path="ml/data/models/features_config.json"
    )
```

---

## 11. Chạy Full Pipeline

```bash
# Chạy toàn bộ ML pipeline từ đầu đến cuối

# 1. Cài dependencies
pip install -r ml/requirements.txt

# 2. Feature extraction từ raw ETW logs thô (.etl)
python ml/src/feature_pipeline.py \
    --benign-dir ml/data/raw/benign/ \
    --malicious-dir ml/data/raw/malicious/ \
    --output ml/data/processed/training_dataset.parquet

# 3. EDA (optional - xem trong notebook)
jupyter notebook ml/notebooks/01_eda.ipynb

# 4. Train models và chọn best
python ml/src/train.py \
    --dataset ml/data/processed/training_dataset.parquet \
    --model lightgbm \
    --output ml/data/models/lgbm_model.pkl

# 5. Hyperparameter optimization
python ml/src/optimize.py \
    --dataset ml/data/processed/training_dataset.parquet \
    --n-trials 100 \
    --output ml/data/models/lgbm_optimized.pkl

# 6. Export sang ONNX
python ml/src/export_onnx.py \
    --model ml/data/models/lgbm_optimized.pkl \
    --output ml/data/models/edr_model_fp32.onnx \
    --n-features 64

# 7. Quantize sang INT8
python ml/src/quantize.py \
    --input ml/data/models/edr_model_fp32.onnx \
    --output ml/data/models/edr_model_int8.onnx \
    --calibration-data ml/data/processed/training_dataset.parquet \
    --method dynamic

# 8. Deploy sang agent
python ml/src/model_registry.py deploy \
    --model ml/data/models/edr_model_int8.onnx \
    --agent-dir agent/models/

# requirements.txt
# numpy>=1.24.0
# pandas>=2.0.0
# scikit-learn>=1.3.0
# xgboost>=2.0.0
# lightgbm>=4.0.0
# onnx>=1.14.0
# onnxruntime>=1.17.0
# skl2onnx>=1.15.0
# onnxmltools>=1.11.0
# optuna>=3.0.0
# mlflow>=2.0.0
# scipy>=1.11.0
# matplotlib>=3.7.0
# seaborn>=0.12.0
# pywin32>=306  # Windows only
```

---

## 12. Expected Model Performance

```
Sau optimization và quantization, model benchmark kỳ vọng:

┌─────────────────────────────────────────────────────────────────┐
│ Metric                     │ Target      │ Notes                │
├─────────────────────────────────────────────────────────────────┤
│ F1-Score (weighted)        │ > 0.90      │ 3-class              │
│ AUC-ROC                    │ > 0.95      │ OvR, weighted        │
│ Detection Rate (Malicious) │ > 85%       │ TP/(TP+FN)           │
│ False Positive Rate        │ < 5%        │ FP/(FP+TN) on benign │
│ Model Size (FP32)          │ < 10 MB     │ LightGBM 300 trees   │
│ Model Size (INT8)          │ < 3 MB      │ After quantization   │
│ Inference Latency (FP32)   │ < 50ms      │ Single event, CPU    │
│ Inference Latency (INT8)   │ < 20ms      │ Single event, CPU    │
│ Accuracy drop (quantize)   │ < 2%        │ FP32 vs INT8         │
└─────────────────────────────────────────────────────────────────┘
```
