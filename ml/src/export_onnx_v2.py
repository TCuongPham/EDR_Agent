# ml/src/export_onnx_v2.py
import os
import shutil
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

def main():
    src_dir = os.path.dirname(__file__)
    models_dir = os.path.abspath(os.path.join(src_dir, "../data/models_v2"))
    agent_models_dir = os.path.abspath(os.path.join(src_dir, "../../agent/configs/models"))
    
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(agent_models_dir, exist_ok=True)
    
    lgb_model_path = os.path.join(models_dir, "best_lgb_model_v2.txt")
    onnx_model_path = os.path.join(models_dir, "edr_model_v2.onnx")
    agent_model_path = os.path.join(agent_models_dir, "edr_model.onnx")
    
    if not os.path.exists(lgb_model_path):
        print(f"[Error] LightGBM model not found at: {lgb_model_path}")
        print("Please run train_v2.py first.")
        return

    print(f"[*] Loading LightGBM model from {lgb_model_path}...")
    model = lgb.Booster(model_file=lgb_model_path)

    # We have exactly 19 features in v2
    input_features_count = 19
    print(f"[*] Converting model to ONNX (Input shape: [1, {input_features_count}])...")
    
    initial_type = [('input', FloatTensorType([1, input_features_count]))]
    
    # Convert LightGBM model to ONNX format with zipmap disabled
    onnx_model = onnxmltools.convert_lightgbm(
        model, 
        initial_types=initial_type, 
        target_opset=15,
        zipmap=False
    )

    print(f"[*] Saving ONNX model to {onnx_model_path}...")
    onnxmltools.utils.save_model(onnx_model, onnx_model_path)
    
    print(f"[*] Copying ONNX model to agent models dir: {agent_model_path}...")
    shutil.copy2(onnx_model_path, agent_model_path)
    
    print("[Done] Model exported to ONNX successfully.")

if __name__ == "__main__":
    main()
