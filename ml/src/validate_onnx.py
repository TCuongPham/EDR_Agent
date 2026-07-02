# ml/src/validate_onnx.py
import os
import numpy as np
import lightgbm as lgb
import onnxruntime as ort
import joblib

def main():
    src_dir = os.path.dirname(__file__)
    models_dir = os.path.abspath(os.path.join(src_dir, "../data/models"))
    
    pkl_path = os.path.join(models_dir, "best_lgb_model.pkl")
    onnx_path = os.path.join(models_dir, "edr_model.onnx")
    quantized_path = os.path.join(models_dir, "edr_model_int8.onnx")
    
    if not os.path.exists(pkl_path) or not os.path.exists(onnx_path):
        print("[Error] Missing models for validation. Please run train.py and export_onnx.py first.")
        return
        
    print("[*] Loading LightGBM model and ONNX sessions...")
    lgb_model = joblib.load(pkl_path)
    ort_session = ort.InferenceSession(onnx_path)
    
    # Generate 100 dummy samples to check
    np.random.seed(42)
    dummy_input = np.random.rand(100, 25).astype(np.float32)
    
    # Python predictions
    py_probs = lgb_model.predict(dummy_input)
    
    # ONNX predictions (evaluate one by one to match batch size 1 of the model)
    input_name = ort_session.get_inputs()[0].name
    onnx_probs_list = []
    for i in range(100):
        sample = dummy_input[i:i+1]
        onnx_results = ort_session.run(None, {input_name: sample})
        
        # Extract probabilities
        onnx_probs_raw = onnx_results[1]
        if isinstance(onnx_probs_raw, list) and len(onnx_probs_raw) > 0 and isinstance(onnx_probs_raw[0], dict):
            prob = np.array([onnx_probs_raw[0][0], onnx_probs_raw[0][1], onnx_probs_raw[0][2]], dtype=np.float32)
        elif isinstance(onnx_probs_raw, list):
            prob = np.array(onnx_probs_raw[0], dtype=np.float32)
        else:
            prob = onnx_probs_raw[0]
        onnx_probs_list.append(prob)
        
    onnx_probs = np.array(onnx_probs_list, dtype=np.float32)
        
    # Check max difference
    diff = np.abs(py_probs - onnx_probs)
    max_diff = np.max(diff)
    mean_diff = np.mean(diff)
    
    print(f"[*] Comparing Python vs ONNX model:")
    print(f"    - Maximum probability difference: {max_diff:.2e}")
    print(f"    - Mean probability difference: {mean_diff:.2e}")
    
    if max_diff < 1e-4:
        print("[Success] ONNX validation passed successfully! Output matches Python Booster.")
    else:
        print("[Warning] ONNX validation warning: differences exceed threshold. Check conversion.")
        
    # Validate quantized version if exists
    if os.path.exists(quantized_path):
        q_session = ort.InferenceSession(quantized_path)
        q_probs_list = []
        for i in range(100):
            sample = dummy_input[i:i+1]
            q_results = q_session.run(None, {input_name: sample})
            q_probs_raw = q_results[1]
            
            if isinstance(q_probs_raw, list) and len(q_probs_raw) > 0 and isinstance(q_probs_raw[0], dict):
                prob = np.array([q_probs_raw[0][0], q_probs_raw[0][1], q_probs_raw[0][2]], dtype=np.float32)
            elif isinstance(q_probs_raw, list):
                prob = np.array(q_probs_raw[0], dtype=np.float32)
            else:
                prob = q_probs_raw[0]
            q_probs_list.append(prob)
            
        q_probs = np.array(q_probs_list, dtype=np.float32)
        q_diff = np.abs(py_probs - q_probs)
        print(f"[*] Comparing Python vs Quantized INT8 ONNX model:")
        print(f"    - Maximum probability difference: {np.max(q_diff):.2e}")
        print(f"    - Mean probability difference: {np.mean(q_diff):.2e}")
        
if __name__ == "__main__":
    main()
