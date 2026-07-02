// agent/src/main.cpp
#include <iostream>
#include <thread>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <atomic>
#include "collector_registry.h"
#include "normalizer.h"
#include "ringbuffer.h"
#include "lineage_graph.h"
#include "sliding_window.h"
#include "features.h"
#include "sqlite3.h"
#include "rule_engine.h"
#include "onnx_inferencer.h"
#include "response.h"
#include "scorer.h"


std::atomic<bool> g_keepRunning(true);

// Helper to convert std::any to nlohmann::json
static nlohmann::json AnyToJson(const std::any& a) {
    if (a.type() == typeid(std::string)) {
        return std::any_cast<std::string>(a);
    } else if (a.type() == typeid(const char*)) {
        return std::string(std::any_cast<const char*>(a));
    } else if (a.type() == typeid(int)) {
        return std::any_cast<int>(a);
    } else if (a.type() == typeid(unsigned int)) {
        return std::any_cast<unsigned int>(a);
    } else if (a.type() == typeid(uint64_t)) {
        return std::any_cast<uint64_t>(a);
    } else if (a.type() == typeid(uint16_t)) {
        return std::any_cast<uint16_t>(a);
    } else if (a.type() == typeid(float)) {
        return std::any_cast<float>(a);
    } else if (a.type() == typeid(double)) {
        return std::any_cast<double>(a);
    } else if (a.type() == typeid(bool)) {
        return std::any_cast<bool>(a);
    }
    return nullptr;
}

// Convert NormalizedEvent to JSON format matching telemetry_spec.md
static nlohmann::json EventToJson(const NormalizedEvent& evt) {
    nlohmann::json j;
    j["id"] = evt.id;
    
    // ISO 8601 formatting for UTC timestamp
    auto time_t = std::chrono::system_clock::to_time_t(evt.timestamp);
    std::tm gmt;
    gmtime_s(&gmt, &time_t);
    std::stringstream ss;
    ss << std::put_time(&gmt, "%Y-%m-%dT%H:%M:%SZ");
    j["timestamp"] = ss.str();
    
    j["eventType"] = evt.eventType;
    j["pid"] = evt.pid;
    j["ppid"] = evt.ppid;
    j["processName"] = evt.processName;
    j["processPath"] = evt.processPath;
    j["commandLine"] = evt.commandLine;
    j["userName"] = evt.userName;
    j["sessionId"] = evt.sessionId;
    j["parentName"] = evt.parentName;
    j["isSystem"] = evt.isSystem;
    j["depth"] = evt.depth;
    
    nlohmann::json fieldsObj = nlohmann::json::object();
    for (const auto& [key, val] : evt.fields) {
        fieldsObj[key] = AnyToJson(val);
    }
    j["fields"] = fieldsObj;
    
    return j;
}

// Thread function that reads normalized events from RingBuffer, extracts features, performs tiered inference, and takes actions.
void EventConsumerThread(std::shared_ptr<RingBuffer> ringBuffer,
                         std::shared_ptr<BehaviorGraph> behaviorGraph,
                         std::shared_ptr<SlidingWindowAggregator> windowAgg,
                         std::shared_ptr<FeatureRegistry> featureRegistry,
                         std::shared_ptr<RuleEngine> ruleEngine,
                         std::shared_ptr<ONNXInferencer> onnxInferencer,
                         std::shared_ptr<ResponseHandler> responseHandler) {
    sqlite3* db = nullptr;
    int rc = sqlite3_open("telemetry_events.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "[Consumer] Error: Could not open telemetry_events.db: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        db = nullptr;
    } else {
        const char* createTableSql = 
            "CREATE TABLE IF NOT EXISTS telemetry_events ("
            "id TEXT PRIMARY KEY, "
            "timestamp TEXT, "
            "eventType TEXT, "
            "pid INTEGER, "
            "ppid INTEGER, "
            "processName TEXT, "
            "processPath TEXT, "
            "commandLine TEXT, "
            "userName TEXT, "
            "sessionId INTEGER, "
            "parentName TEXT, "
            "isSystem INTEGER, "
            "depth INTEGER, "
            "fields TEXT, "
            "features TEXT"
            ");";
        char* errMsg = nullptr;
        rc = sqlite3_exec(db, createTableSql, nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "[Consumer] Error creating table: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
    }

    std::cout << "[Consumer] Event processing loop started." << std::endl;

    while (g_keepRunning) {
        auto evt = ringBuffer->Pop();
        if (!evt) continue;

        // Skip dummy shutdown event
        if (evt->pid == 0 && evt->processName.empty() && evt->eventType.empty()) {
            continue;
        }

        // 1. Update graphs / windows for active events
        if (evt->eventType == "ProcessCreate") {
            auto node = std::make_shared<ProcessNode>();
            node->pid = evt->pid;
            node->ppid = evt->ppid;
            node->name = evt->processName;
            node->path = evt->processPath;
            node->commandLine = evt->commandLine;
            node->startTime = evt->timestamp;
            behaviorGraph->AddProcess(node);
        } else if (evt->eventType == "ProcessAccess") {
            auto node = behaviorGraph->GetNode(evt->pid);
            if (node) {
                node->SetAttribute("lsass_access", "1");
            }
        }

        // 2. Update sliding window aggregator for non-terminate events
        if (evt->eventType != "ProcessTerminate") {
            windowAgg->Update(evt);
        }

        // Tier-1: Fast Whitelist / Rule Filter
        RuleDecision ruleDecision = ruleEngine->Evaluate(evt);
        
        // Setup ScoringContext
        ScoringContext scoringCtx;
        scoringCtx.event = evt;

        if (ruleDecision == RuleDecision::RuleDecisionClean) {
            // Discard clean whitelisted events to save CPU, but keep their lineage/windows intact
            if (evt->eventType == "ProcessTerminate") {
                behaviorGraph->RemoveProcess(evt->pid);
                windowAgg->RemoveProcess(evt->pid);
            }
            continue;
        }

        // 3. Extract feature vector while process context is fully intact
        auto startFeat = std::chrono::high_resolution_clock::now();
        auto features = featureRegistry->Vectorize(evt->pid, evt, behaviorGraph, windowAgg);
        auto endFeat = std::chrono::high_resolution_clock::now();
        double featMs = std::chrono::duration<double, std::milli>(endFeat - startFeat).count();
        scoringCtx.featureVector = features;

        // 4. Clean up tracking data after vectorization is complete
        if (evt->eventType == "ProcessTerminate") {
            behaviorGraph->RemoveProcess(evt->pid);
            windowAgg->RemoveProcess(evt->pid);
        }

        // Tier-2: ML Model Inference
        auto startInfer = std::chrono::high_resolution_clock::now();
        float mlScore = onnxInferencer->Infer(features);
        auto endInfer = std::chrono::high_resolution_clock::now();
        double inferMs = std::chrono::duration<double, std::milli>(endInfer - startInfer).count();
        scoringCtx.mlScore = mlScore;

        // Tier-3: Behavioral Graph Correlation
        auto lineage = behaviorGraph->GetLineage(evt->pid);
        for (const auto& node : lineage) {
            scoringCtx.lineage.push_back(node->name);
        }

        bool patternMatch = false;
        if (behaviorGraph->MatchPattern(evt->pid, {"winword.exe", "powershell.exe"}) ||
            behaviorGraph->MatchPattern(evt->pid, {"excel.exe", "powershell.exe"}) ||
            behaviorGraph->MatchPattern(evt->pid, {"outlook.exe", "cmd.exe"}) ||
            behaviorGraph->MatchPattern(evt->pid, {"winword.exe", "cmd.exe"}) ||
            behaviorGraph->MatchPattern(evt->pid, {"excel.exe", "cmd.exe"})) {
            patternMatch = true;
        }
        scoringCtx.patternMatch = patternMatch;

        // Overwrite or elevate score if rule is critical
        if (ruleDecision == RuleDecision::RuleDecisionCritical) {
            scoringCtx.graphScore = 1.0f;
            patternMatch = true;
            scoringCtx.patternMatch = true;
        }

        // 5. Trigger Response Actions
        responseHandler->Handle(scoringCtx);

        // 6. Convert to JSON with features (used for stdout display and text fields)
        nlohmann::json j = EventToJson(*evt);
        j["features"] = features;
        j["ml_score"] = mlScore;
        j["final_score"] = scoringCtx.FinalScore();
        std::string jsonStr = j.dump();

        // Print to console (stdout)
        std::cout << "[EVENT] " << jsonStr << std::endl;
        std::cout << "[INFERENCE] PID " << evt->pid << " (" << evt->processName << ") "
                  << "-> ML Score: " << mlScore << " | Final Score: " << scoringCtx.FinalScore() 
                  << " (" << ScoreToLevel(scoringCtx.FinalScore()) << ")"
                  << " | Latency: Feat=" << std::fixed << std::setprecision(3) << featMs << "ms, ML=" << inferMs << "ms" << std::endl;

        // Log to SQLite Database
        if (db) {
            const char* insertSql = 
                "INSERT INTO telemetry_events (id, timestamp, eventType, pid, ppid, processName, "
                "processPath, commandLine, userName, sessionId, parentName, isSystem, depth, fields, features) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
            sqlite3_stmt* stmt = nullptr;
            rc = sqlite3_prepare_v2(db, insertSql, -1, &stmt, nullptr);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, evt->id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, j["timestamp"].get<std::string>().c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, evt->eventType.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt, 4, evt->pid);
                sqlite3_bind_int(stmt, 5, evt->ppid);
                sqlite3_bind_text(stmt, 6, evt->processName.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 7, evt->processPath.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 8, evt->commandLine.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 9, evt->userName.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt, 10, evt->sessionId);
                sqlite3_bind_text(stmt, 11, evt->parentName.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt, 12, evt->isSystem ? 1 : 0);
                sqlite3_bind_int(stmt, 13, evt->depth);
                
                std::string fieldsStr = j["fields"].dump();
                sqlite3_bind_text(stmt, 14, fieldsStr.c_str(), -1, SQLITE_TRANSIENT);
                
                std::string featuresStr = j["features"].dump();
                sqlite3_bind_text(stmt, 15, featuresStr.c_str(), -1, SQLITE_TRANSIENT);

                rc = sqlite3_step(stmt);
                if (rc != SQLITE_DONE) {
                    std::cerr << "[Consumer] Warning: Failed to insert event: " << sqlite3_errmsg(db) << std::endl;
                }
                sqlite3_finalize(stmt);
            } else {
                std::cerr << "[Consumer] Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
            }
        }
    }
    
    if (db) {
        sqlite3_close(db);
    }
    std::cout << "[Consumer] Event processing loop stopped." << std::endl;
}

// Helper to parse a RawEvent from JSON for mock testing
static RawEvent RawEventFromJson(const nlohmann::json& j) {
    RawEvent raw{};
    raw.timestamp = j.value("timestamp", 0LL);
    
    std::string typeStr = j.value("eventType", "");
    if (typeStr == "EventProcessCreate" || typeStr == "ProcessCreate") {
        raw.eventType = EventType::EventProcessCreate;
    } else if (typeStr == "EventProcessTerminate" || typeStr == "ProcessTerminate") {
        raw.eventType = EventType::EventProcessTerminate;
    } else if (typeStr == "EventRegistrySet" || typeStr == "RegistrySet") {
        raw.eventType = EventType::EventRegistrySet;
    } else if (typeStr == "EventRegistryCreate" || typeStr == "RegistryCreate") {
        raw.eventType = EventType::EventRegistryCreate;
    } else if (typeStr == "EventProcessAccess" || typeStr == "ProcessAccess") {
        raw.eventType = EventType::EventProcessAccess;
    }
    
    raw.pid = j.value("pid", 0U);
    raw.ppid = j.value("ppid", 0U);
    raw.tid = j.value("tid", 0U);
    raw.sessionId = j.value("sessionId", 0U);

    std::string procName = j.value("processName", "");
#if defined(_WIN32)
    strncpy_s(raw.processName, procName.c_str(), sizeof(raw.processName) - 1);
#else
    strncpy(raw.processName, procName.c_str(), sizeof(raw.processName) - 1);
#endif
    
    std::string cmdLine = j.value("commandLine", "");
#if defined(_WIN32)
    strncpy_s(raw.commandLine, cmdLine.c_str(), sizeof(raw.commandLine) - 1);
#else
    strncpy(raw.commandLine, cmdLine.c_str(), sizeof(raw.commandLine) - 1);
#endif
    
    std::string imgPath = j.value("imagePath", "");
#if defined(_WIN32)
    strncpy_s(raw.imagePath, imgPath.c_str(), sizeof(raw.imagePath) - 1);
#else
    strncpy(raw.imagePath, imgPath.c_str(), sizeof(raw.imagePath) - 1);
#endif

    std::string keyPath = j.value("regKeyPath", "");
#if defined(_WIN32)
    strncpy_s(raw.regKeyPath, keyPath.c_str(), sizeof(raw.regKeyPath) - 1);
#else
    strncpy(raw.regKeyPath, keyPath.c_str(), sizeof(raw.regKeyPath) - 1);
#endif

    std::string regVal = j.value("regValue", "");
#if defined(_WIN32)
    strncpy_s(raw.regValue, regVal.c_str(), sizeof(raw.regValue) - 1);
#else
    strncpy(raw.regValue, regVal.c_str(), sizeof(raw.regValue) - 1);
#endif

    raw.targetPid = j.value("targetPid", 0U);
    raw.accessRights = j.value("accessRights", 0U);

    return raw;
}

int main(int argc, char* argv[]) {
    std::cout << "===========================================" << std::endl;
    std::cout << "      EDR AI Agent — Integrated Engine     " << std::endl;
    std::cout << "===========================================" << std::endl;

    bool testMode = false;
    std::string testEventsPath = "";
    std::string configPath = "configs/agent_config.json";

    if (argc > 1) {
        std::string arg1 = argv[1];
        if (arg1 == "-test" && argc > 2) {
            testMode = true;
            testEventsPath = argv[2];
            if (argc > 3) {
                configPath = argv[3];
            }
            std::cout << "[TestMode] Running offline simulation test using: " << testEventsPath << std::endl;
        } else {
            configPath = argv[1];
        }
    }

    // Resolve paths relative to configuration directory
    std::string featuresConfigPath = "configs/features_config.json";
    std::string scalerParamsPath = "configs/scaler_params.json";
    std::string modelPath = "models/edr_model.onnx";
    std::string responsePolicyPath = "configs/response_policy.json";

    std::ifstream confFile(configPath);
    nlohmann::json configJson;
    if (confFile.is_open()) {
        try {
            confFile >> configJson;
            if (configJson.contains("features_config_path")) {
                featuresConfigPath = configJson["features_config_path"].get<std::string>();
            }
            if (configJson.contains("scaler_params_path")) {
                scalerParamsPath = configJson["scaler_params_path"].get<std::string>();
            }
            if (configJson.contains("model_path")) {
                modelPath = configJson["model_path"].get<std::string>();
            }
            if (configJson.contains("response_policy_path")) {
                responsePolicyPath = configJson["response_policy_path"].get<std::string>();
            }
        } catch (const std::exception& e) {
            std::cerr << "[Config] Warning: Failed to parse configuration file: " << e.what() << std::endl;
        }
    }

    // Smart helper to resolve paths relative to config file directory
    auto resolvePath = [](const std::string& basePath, const std::string& relPath) -> std::string {
        if (relPath.size() > 1 && relPath[1] == ':') return relPath;
        if (relPath.size() > 0 && relPath[0] == '/') return relPath;
        size_t found = basePath.find_last_of("/\\");
        if (found == std::string::npos) return relPath;
        std::string baseDir = basePath.substr(0, found + 1); // e.g. "agent/configs/"
        std::string targetPath = baseDir + relPath;
        std::ifstream f(targetPath);
        if (f.good()) return targetPath;
        
        // Strip duplicate "configs/" if baseDir ends with configs/ and relPath starts with configs/
        if (baseDir.size() >= 8 && baseDir.substr(baseDir.size() - 8) == "configs/" && relPath.substr(0, 8) == "configs/") {
            std::string strippedPath = baseDir + relPath.substr(8);
            std::ifstream sf(strippedPath);
            if (sf.good()) return strippedPath;
        }

        // Try parent dir
        if (baseDir.size() > 1) {
            size_t parentFound = baseDir.substr(0, baseDir.size() - 1).find_last_of("/\\");
            if (parentFound != std::string::npos) {
                std::string parentDir = baseDir.substr(0, parentFound + 1);
                std::string parentPath = parentDir + relPath;
                std::ifstream pf(parentPath);
                if (pf.good()) return parentPath;
            }
        }
        return targetPath;
    };

    std::string resolvedFeaturesPath = resolvePath(configPath, featuresConfigPath);
    std::string resolvedScalerPath = resolvePath(configPath, scalerParamsPath);
    std::string resolvedModelPath = resolvePath(configPath, modelPath);
    std::string resolvedResponsePolicyPath = resolvePath(configPath, responsePolicyPath);

    // Initialize telemetry normalizer, ring buffer, lineage graph and windows
    int ringBufferSize = configJson.value("ring_buffer_size", 65536);
    auto ringBuffer = std::make_shared<RingBuffer>(ringBufferSize);
    auto behaviorGraph = std::make_shared<BehaviorGraph>(10000);
    auto windowAgg = std::make_shared<SlidingWindowAggregator>();
    auto featureRegistry = std::make_shared<FeatureRegistry>();

    if (!featureRegistry->LoadConfig(resolvedFeaturesPath)) {
        std::cerr << "[Warning] Could not load feature configuration from " << resolvedFeaturesPath << std::endl;
    }
    if (!featureRegistry->LoadScalerParams(resolvedScalerPath)) {
        std::cerr << "[Warning] Could not load scaler parameters from " << resolvedScalerPath << std::endl;
    }

    // Instantiate Tiered Inference & Response Components
    std::wstring wModelPath(resolvedModelPath.begin(), resolvedModelPath.end());
    auto ruleEngine = std::make_shared<RuleEngine>();
    auto onnxInferencer = std::make_shared<ONNXInferencer>(wModelPath);
    auto responseHandler = std::make_shared<ResponseHandler>(resolvedResponsePolicyPath);

    // Start consumer thread
    std::thread consumerThread(EventConsumerThread, ringBuffer, behaviorGraph, windowAgg, featureRegistry, ruleEngine, onnxInferencer, responseHandler);

    CollectorRegistry registry;

    if (testMode) {
        // --- OFFLINE TEST MODE ---
        std::ifstream testFile(testEventsPath);
        if (!testFile.is_open()) {
            std::cerr << "[TestMode] Error: Could not open mock events file at " << testEventsPath << std::endl;
        } else {
            try {
                nlohmann::json testJson;
                testFile >> testJson;
                
                std::cout << "[TestMode] Injecting mock telemetry events..." << std::endl;
                Normalizer normalizer;
                
                for (const auto& item : testJson["events"]) {
                    RawEvent raw = RawEventFromJson(item);
                    auto normalized = normalizer.Normalize(raw);
                    if (normalized) {
                        ringBuffer->Push(normalized);
                    }
                }
                std::cout << "[TestMode] All mock events injected. Waiting for processing to finish..." << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "[TestMode] Error parsing mock events: " << e.what() << std::endl;
            }
        }
        
        // Give processing thread a moment to drain the queue
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        
        std::cout << "[TestMode] Auto-shutdown initiated." << std::endl;
        g_keepRunning = false;
        
        // Wake up blocking Pop
        auto dummyEvent = std::make_shared<NormalizedEvent>();
        ringBuffer->Push(dummyEvent);
    } else {
        // --- LIVE ETW MODE ---
        // Setup raw collectors and callback
        auto normalizerObj = std::make_shared<Normalizer>();
        auto eventCallback = [normalizerObj, ringBuffer](const RawEvent& raw) {
            auto normalized = normalizerObj->Normalize(raw);
            if (normalized) {
                ringBuffer->Push(normalized);
            }
        };

        auto processCollector = std::make_shared<ETWConsumer>(
            L"EDR_Process_Session",
            "process",
            std::vector<std::pair<std::wstring, uint64_t>>{
                { L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", 0x10 } // Microsoft-Windows-Kernel-Process (Process keyword)
            },
            eventCallback
        );

        auto processAccessCollector = std::make_shared<ETWConsumer>(
            L"EDR_ProcessAccess_Session",
            "process_access",
            std::vector<std::pair<std::wstring, uint64_t>>{
                { L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", 0x20 } // Microsoft-Windows-Kernel-Process (Thread keyword)
            },
            eventCallback
        );

        auto fileCollector = std::make_shared<ETWConsumer>(
            L"EDR_File_Session",
            "file",
            std::vector<std::pair<std::wstring, uint64_t>>{
                { L"{edd08927-9cc4-4e65-b970-c2560fb5c289}", 0x10 } // Microsoft-Windows-Kernel-File (File keyword)
            },
            eventCallback
        );

        auto networkCollector = std::make_shared<ETWConsumer>(
            L"EDR_Network_Session",
            "network",
            std::vector<std::pair<std::wstring, uint64_t>>{
                { L"{7dd42a49-5329-4832-8dfd-43d979153a88}", 0x40 } // Microsoft-Windows-Kernel-Network (TcpIp keyword)
            },
            eventCallback
        );

        auto registryCollector = std::make_shared<ETWConsumer>(
            L"EDR_Registry_Session",
            "registry",
            std::vector<std::pair<std::wstring, uint64_t>>{
                { L"{70eb4f03-c1de-4f73-a051-33d13d5413bd}", 0x1 } // Microsoft-Windows-Kernel-Registry (Registry keyword)
            },
            eventCallback
        );

        registry.RegisterCollector(processCollector);
        registry.RegisterCollector(processAccessCollector);
        registry.RegisterCollector(fileCollector);
        registry.RegisterCollector(networkCollector);
        registry.RegisterCollector(registryCollector);

        if (!registry.LoadConfigAndStart(configPath)) {
            std::cerr << "[!] Error loading config or starting collectors. Make sure config path is correct and you are running as Administrator." << std::endl;
            g_keepRunning = false;
            auto dummyEvent = std::make_shared<NormalizedEvent>();
            ringBuffer->Push(dummyEvent);
            if (consumerThread.joinable()) consumerThread.join();
            return 1;
        }

        std::cout << "\n[*] Telemetry collection active. Press Enter to shutdown EDR agent..." << std::endl;
        std::cin.get();

        std::cout << "[*] Shutdown initiated..." << std::endl;
        g_keepRunning = false;
        
        // Wake up blocking Pop
        auto dummyEvent = std::make_shared<NormalizedEvent>();
        ringBuffer->Push(dummyEvent);

        registry.StopAll();
    }

    if (consumerThread.joinable()) {
        consumerThread.join();
    }

    std::cout << "[*] EDR Agent stopped successfully." << std::endl;
    return 0;
}