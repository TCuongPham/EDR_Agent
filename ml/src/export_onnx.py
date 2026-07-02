# ml/src/export_onnx.py
import os
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

def main():
    src_dir = os.path.dirname(__file__)
    models_dir = os.path.abspath(os.path.join(src_dir, "../data/models"))
    
    lgb_model_path = os.path.join(models_dir, "best_lgb_model.txt")
    onnx_model_path = os.path.join(models_dir, "edr_model.onnx")
    
    if not os.path.exists(lgb_model_path):
        print(f"[Error] LightGBM model not found at: {lgb_model_path}")
        print("Please run train.py first to train and save the model.")
        return

    print(f"[*] Loading LightGBM model from {lgb_model_path}...")
    model = lgb.Booster(model_file=lgb_model_path)

    # We have exactly 27 features (excluding file and network features)
    input_features_count = 25
    print(f"[*] Converting model to ONNX (Input shape: [1, {input_features_count}])...")
    
    initial_type = [('input', FloatTensorType([1, input_features_count]))]
    
    # Convert LightGBM model to ONNX format (using opset 15 for wide compatibility)
    onnx_model = onnxmltools.convert_lightgbm(
        model, 
        initial_types=initial_type, 
        target_opset=15
    )

    print(f"[*] Saving ONNX model to {onnx_model_path}...")
    onnxmltools.utils.save_model(onnx_model, onnx_model_path)
    print("[Done] Model exported to ONNX successfully.")

if __name__ == "__main__":
    main()
