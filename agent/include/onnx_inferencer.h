// agent/include/onnx_inferencer.h
#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <memory>
#include <onnxruntime_cxx_api.h>

class ONNXInferencer {
private:
    Ort::Env m_env;
    std::unique_ptr<Ort::Session> m_session;
    std::vector<std::string> m_inputNamesAllocated;
    std::vector<std::string> m_outputNamesAllocated;
    std::vector<const char*> m_inputNames;
    std::vector<const char*> m_outputNames;
    std::vector<int64_t> m_inputShape;

public:
    ONNXInferencer(const std::wstring& modelPath) 
        : m_env(ORT_LOGGING_LEVEL_WARNING, "EDR_AI_Agent") {
        
        try {
            Ort::SessionOptions sessionOptions;
            sessionOptions.SetIntraOpNumThreads(1);
            sessionOptions.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
            sessionOptions.DisableMemPattern();

            m_session = std::make_unique<Ort::Session>(m_env, modelPath.c_str(), sessionOptions);

            // Dynamic query of input shape and tensor names
            Ort::AllocatorWithDefaultOptions allocator;
            
            // 1. Get input details
            size_t numInputNodes = m_session->GetInputCount();
            for (size_t i = 0; i < numInputNodes; ++i) {
                auto inputName = m_session->GetInputNameAllocated(i, allocator);
                m_inputNamesAllocated.push_back(inputName.get());
                
                Ort::TypeInfo typeInfo = m_session->GetInputTypeInfo(i);
                auto tensorInfo = typeInfo.GetTensorTypeAndShapeInfo();
                m_inputShape = tensorInfo.GetShape();
                
                // Ensure batch size = 1
                if (!m_inputShape.empty() && m_inputShape[0] < 0) {
                    m_inputShape[0] = 1; 
                }
            }
            
            // 2. Get output details
            size_t numOutputNodes = m_session->GetOutputCount();
            for (size_t i = 0; i < numOutputNodes; ++i) {
                auto outputName = m_session->GetOutputNameAllocated(i, allocator);
                m_outputNamesAllocated.push_back(outputName.get());
            }

            // Create raw pointers for Session::Run
            for (const auto& name : m_inputNamesAllocated) {
                m_inputNames.push_back(name.c_str());
            }
            for (const auto& name : m_outputNamesAllocated) {
                m_outputNames.push_back(name.c_str());
            }
            
            std::cout << "[ONNXInferencer] Loaded model from: " << std::string(modelPath.begin(), modelPath.end()) << std::endl;
            std::cout << "[ONNXInferencer] Input shape expectation: [";
            for (size_t i = 0; i < m_inputShape.size(); ++i) {
                std::cout << m_inputShape[i] << (i == m_inputShape.size() - 1 ? "" : ", ");
            }
            std::cout << "]" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[ONNXInferencer] Initialization exception: " << e.what() << std::endl;
            m_session = nullptr;
        }
    }

    float Infer(const std::vector<float>& features) {
        if (!m_session) {
            std::cerr << "[ONNXInferencer] Error: Session is null, cannot infer!" << std::endl;
            return 0.0f;
        }

        // Validate features size with expected shape
        int64_t expectedFeatures = 1;
        for (size_t i = 1; i < m_inputShape.size(); ++i) {
            expectedFeatures *= m_inputShape[i];
        }
        
        if (features.size() != static_cast<size_t>(expectedFeatures)) {
            std::cerr << "[ONNXInferencer] Feature vector dimension mismatch! Model expected " 
                      << expectedFeatures << ", but got " << features.size() << std::endl;
            return 0.0f;
        }

        try {
            Ort::MemoryInfo memoryInfo = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
            
            // Create input tensor (non-owning wrapper over features data)
            Ort::Value inputTensor = Ort::Value::CreateTensor<float>(
                memoryInfo, 
                const_cast<float*>(features.data()), 
                features.size(), 
                m_inputShape.data(), 
                m_inputShape.size()
            );

            // Run model
            auto outputTensors = m_session->Run(
                Ort::RunOptions{nullptr}, 
                m_inputNames.data(), &inputTensor, 1, 
                m_outputNames.data(), m_outputNames.size()
            );

            // Multiclass probabilities: shape [1, 3] -> P(Benign), P(Malware), P(Credential)
            float* probabilities = outputTensors[1].GetTensorMutableData<float>();
            
            // Custom threat scoring formula:
            // P(Benign) * 0.0 + P(Malware) * 0.5 + P(Credential) * 1.0
            float threatScore = probabilities[1] * 0.5f + probabilities[2] * 1.0f;
            
            return std::clamp(threatScore, 0.0f, 1.0f);
        } catch (const std::exception& e) {
            std::cerr << "[ONNXInferencer] Inference exception: " << e.what() << std::endl;
            return 0.0f;
        }
    }
};
