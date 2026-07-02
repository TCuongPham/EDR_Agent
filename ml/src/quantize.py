# ml/src/quantize.py
import os
from onnxruntime.quantization import quantize_dynamic, QuantType

def main():
    src_dir = os.path.dirname(__file__)
    models_dir = os.path.abspath(os.path.join(src_dir, "../data/models"))
    
    onnx_path = os.path.join(models_dir, "edr_model.onnx")
    quantized_path = os.path.join(models_dir, "edr_model_int8.onnx")
    
    if not os.path.exists(onnx_path):
        print(f"[Error] ONNX model not found at: {onnx_path}")
        print("Please run export_onnx.py first to export the model.")
        return

    print(f"[*] Quantizing {onnx_path} to INT8...")
    
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
    print(f"[Done] Quantized model saved to: {quantized_path}")

if __name__ == "__main__":
    main()
