# ml/src/quantize_v2.py
# Lượng tử hóa (INT8) mô hình ONNX binary (16 features: Benign vs Malware)
# Chạy sau export_onnx_v2.py để giảm kích thước model trước khi deploy vào agent.
import os
import shutil
from onnxruntime.quantization import quantize_dynamic, QuantType

def main():
    src_dir = os.path.dirname(__file__)
    models_dir = os.path.abspath(os.path.join(src_dir, "../data/models_v2"))
    agent_models_dir = os.path.abspath(os.path.join(src_dir, "../../agent/configs/models"))
    
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(agent_models_dir, exist_ok=True)
    
    onnx_path = os.path.join(models_dir, "edr_model_v2.onnx")
    quantized_path = os.path.join(models_dir, "edr_model_v2_int8.onnx")
    agent_model_path = os.path.join(agent_models_dir, "edr_model.onnx")
    
    if not os.path.exists(onnx_path):
        print(f"[Error] ONNX model not found at: {onnx_path}")
        print("Please run export_onnx_v2.py first.")
        return

    print(f"[*] Quantizing v2 model {onnx_path} to INT8...")
    
    # Apply dynamic quantization to the weights
    quantize_dynamic(
        model_input=onnx_path,
        model_output=quantized_path,
        weight_type=QuantType.QUInt8
    )
    
    # Compare sizes
    orig_size = os.path.getsize(onnx_path) / 1024
    quant_size = os.path.getsize(quantized_path) / 1024
    
    print(f"[*] Original model size: {orig_size:.2f} KB")
    print(f"[*] Quantized model size: {quant_size:.2f} KB (Reduction: {(1 - quant_size/orig_size)*100:.1f}%)")
    
    print(f"[*] Copying quantized ONNX model to agent models dir: {agent_model_path}...")
    shutil.copy2(quantized_path, agent_model_path)
    
    print(f"[Done] Quantized model successfully loaded for EDR Agent.")

if __name__ == "__main__":
    main()
