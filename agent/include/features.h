// agent/include/features.h
#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <algorithm>
#include <functional>
#include <fstream>
#include <iostream>
#include "normalized_event.h"
#include "lineage_graph.h"
#include "sliding_window.h"
#include "entropy.h"
#include "nlohmann/json.hpp"

class IFeatureExtractor {
public:
    virtual ~IFeatureExtractor() = default;
    virtual float Extract(uint32_t pid, std::shared_ptr<NormalizedEvent> evt,
                          std::shared_ptr<BehaviorGraph> graph,
                          std::shared_ptr<SlidingWindowAggregator> windowAgg) = 0;
    virtual std::string GetName() const = 0;
};

using ExtractorFunc = std::function<float(uint32_t pid, std::shared_ptr<NormalizedEvent> evt,
                                         std::shared_ptr<BehaviorGraph> graph,
                                         std::shared_ptr<SlidingWindowAggregator> windowAgg)>;

class LambdaExtractor : public IFeatureExtractor {
private:
    std::string m_name;
    ExtractorFunc m_func;
public:
    LambdaExtractor(const std::string& name, ExtractorFunc func) : m_name(name), m_func(func) {}
    float Extract(uint32_t pid, std::shared_ptr<NormalizedEvent> evt,
                  std::shared_ptr<BehaviorGraph> graph,
                  std::shared_ptr<SlidingWindowAggregator> windowAgg) override {
        return m_func(pid, evt, graph, windowAgg);
    }
    std::string GetName() const override { return m_name; }
};

struct FeatureConfig {
    int index;
    std::string name;
    std::string type;
    float defaultValue;
    std::string namespaceName;
};

struct ScalerRange {
    float min = 0.0f;
    float max = 0.0f;
};

class FeatureRegistry {
public:
    static std::string GetBaseName(const std::string& path) {
        size_t found = path.find_last_of("/\\");
        if (found != std::string::npos) {
            return path.substr(found + 1);
        }
        return path;
    }

private:
    std::unordered_map<std::string, std::shared_ptr<IFeatureExtractor>> m_extractors;
    std::vector<FeatureConfig> m_activeFeatures;
    std::unordered_map<std::string, ScalerRange> m_scalerParams;

    void RegisterBuiltinExtractors() {
        // Feature 0: child_spawn_count_5s
        RegisterExtractor(std::make_shared<LambdaExtractor>("child_spawn_count_5s", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                return static_cast<float>(windowAgg->GetChildSpawnCount(pid, std::chrono::seconds(5)));
            }));

        // Feature 1: child_spawn_count_30s
        RegisterExtractor(std::make_shared<LambdaExtractor>("child_spawn_count_30s", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                return static_cast<float>(windowAgg->GetChildSpawnCount(pid, std::chrono::seconds(30)));
            }));

        // Feature 2: child_spawn_count_300s
        RegisterExtractor(std::make_shared<LambdaExtractor>("child_spawn_count_300s", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                return static_cast<float>(windowAgg->GetChildSpawnCount(pid, std::chrono::seconds(300)));
            }));

        // Feature 3: cmdline_length
        RegisterExtractor(std::make_shared<LambdaExtractor>("cmdline_length", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                return static_cast<float>(evt->commandLine.length());
            }));

        // Feature 4: cmdline_entropy
        RegisterExtractor(std::make_shared<LambdaExtractor>("cmdline_entropy", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                return EntropyCalculator::CmdlineEntropy(evt->commandLine);
            }));

        // Feature 5: has_encoded_cmdline
        RegisterExtractor(std::make_shared<LambdaExtractor>("has_encoded_cmdline", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string cmd = evt->commandLine;
                std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
                if (cmd.find(" -enc") != std::string::npos ||
                    cmd.find(" -encoded") != std::string::npos ||
                    cmd.find(" /enc") != std::string::npos ||
                    cmd.find(" -e ") != std::string::npos) {
                    return 1.0f;
                }
                return 0.0f;
            }));

        // Feature 6: has_download_cradle
        RegisterExtractor(std::make_shared<LambdaExtractor>("has_download_cradle", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string cmd = evt->commandLine;
                std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
                if (cmd.find("invoke-webrequest") != std::string::npos ||
                    cmd.find("iwr") != std::string::npos ||
                    cmd.find("downloadfile") != std::string::npos ||
                    cmd.find("downloadstring") != std::string::npos ||
                    cmd.find("webclient") != std::string::npos ||
                    cmd.find("curl") != std::string::npos ||
                    cmd.find("wget") != std::string::npos ||
                    (cmd.find("certutil") != std::string::npos && cmd.find("-urlcache") != std::string::npos)) {
                    return 1.0f;
                }
                return 0.0f;
            }));

        // Feature 7: cmdline_suspicious_kw_count
        RegisterExtractor(std::make_shared<LambdaExtractor>("cmdline_suspicious_kw_count", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string cmd = evt->commandLine;
                std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
                const std::vector<std::string> keywords = {
                    "bypass", "hidden", "noprofile", "encodedcommand", "downloadstring",
                    "downloadfile", "lsass", "procdump", "minidump", "sekurlsa",
                    "mimikatz", "comsvcs", "rundll32", "regsvr32", "certutil", "vssadmin", "shadowcopy"
                };
                float count = 0.0f;
                for (const auto& kw : keywords) {
                    size_t pos = cmd.find(kw);
                    while (pos != std::string::npos) {
                        count += 1.0f;
                        pos = cmd.find(kw, pos + kw.length());
                    }
                }
                return count;
            }));

        // Feature 8: is_lolbin
        RegisterExtractor(std::make_shared<LambdaExtractor>("is_lolbin", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string name = FeatureRegistry::GetBaseName(evt->processName);
                std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                const std::unordered_set<std::string> lolbins = {
                    "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
                    "certutil.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "bitsadmin.exe", "schtasks.exe", "psexec.exe", "wmic.exe"
                };
                return lolbins.count(name) ? 1.0f : 0.0f;
            }));

        // Feature 9: parent_is_lolbin
        RegisterExtractor(std::make_shared<LambdaExtractor>("parent_is_lolbin", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string parent = FeatureRegistry::GetBaseName(evt->parentName);
                std::transform(parent.begin(), parent.end(), parent.begin(), ::tolower);
                const std::unordered_set<std::string> lolbins = {
                    "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
                    "certutil.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "bitsadmin.exe", "schtasks.exe", "psexec.exe", "wmic.exe"
                };
                return lolbins.count(parent) ? 1.0f : 0.0f;
            }));

        // Feature 10: token_elevated
        RegisterExtractor(std::make_shared<LambdaExtractor>("token_elevated", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                if (evt->isSystem) return 1.0f;
                std::string user = evt->userName;
                std::transform(user.begin(), user.end(), user.begin(), ::tolower);
                if (user.find("system") != std::string::npos || user.find("admin") != std::string::npos) {
                    return 1.0f;
                }
                return 0.0f;
            }));

        // Feature 11: process_depth_in_tree
        RegisterExtractor(std::make_shared<LambdaExtractor>("process_depth_in_tree", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                return static_cast<float>(graph->GetDepth(pid));
            }));

        // Feature 12: parent_is_office
        RegisterExtractor(std::make_shared<LambdaExtractor>("parent_is_office", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string parent = FeatureRegistry::GetBaseName(evt->parentName);
                std::transform(parent.begin(), parent.end(), parent.begin(), ::tolower);
                const std::unordered_set<std::string> office = {
                    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                    "msaccess.exe", "publisher.exe", "winproj.exe", "visio.exe"
                };
                return office.count(parent) ? 1.0f : 0.0f;
            }));

        // Feature 13: parent_is_browser
        RegisterExtractor(std::make_shared<LambdaExtractor>("parent_is_browser", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string parent = FeatureRegistry::GetBaseName(evt->parentName);
                std::transform(parent.begin(), parent.end(), parent.begin(), ::tolower);
                const std::unordered_set<std::string> browsers = {
                    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
                    "opera.exe", "brave.exe", "safari.exe"
                };
                return browsers.count(parent) ? 1.0f : 0.0f;
            }));

        // Feature 14: parent_is_script_engine
        RegisterExtractor(std::make_shared<LambdaExtractor>("parent_is_script_engine", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string parent = FeatureRegistry::GetBaseName(evt->parentName);
                std::transform(parent.begin(), parent.end(), parent.begin(), ::tolower);
                const std::unordered_set<std::string> engines = {
                    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash.exe"
                };
                return engines.count(parent) ? 1.0f : 0.0f;
            }));

        // Feature 15: is_in_temp_path
        RegisterExtractor(std::make_shared<LambdaExtractor>("is_in_temp_path", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string path = evt->processPath;
                std::transform(path.begin(), path.end(), path.begin(), ::tolower);
                if (path.find("\\temp\\") != std::string::npos ||
                    path.find("\\tmp\\") != std::string::npos ||
                    path.find("\\appdata\\local\\temp") != std::string::npos ||
                    path.find("\\windows\\temp") != std::string::npos) {
                    return 1.0f;
                }
                return 0.0f;
            }));

        // Feature 16: is_in_system_path
        RegisterExtractor(std::make_shared<LambdaExtractor>("is_in_system_path", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string path = evt->processPath;
                std::transform(path.begin(), path.end(), path.begin(), ::tolower);
                if (path.find("\\windows\\system32\\") != std::string::npos ||
                    path.find("\\windows\\syswow64\\") != std::string::npos) {
                    return 1.0f;
                }
                return 0.0f;
            }));

        // Feature 17: lifetime_ms_log
        RegisterExtractor(std::make_shared<LambdaExtractor>("lifetime_ms_log", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                if (evt->eventType == "ProcessTerminate") {
                    auto node = graph->GetNode(pid);
                    if (node && node->startTime != std::chrono::system_clock::time_point()) {
                        auto duration = evt->timestamp - node->startTime;
                        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
                        if (ms >= 0) {
                            return std::log1p(static_cast<float>(ms));
                        }
                    }
                }
                return -1.0f; // Default missing value
            }));

        // Feature 18: unusual_parent_child
        RegisterExtractor(std::make_shared<LambdaExtractor>("unusual_parent_child", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string parent = FeatureRegistry::GetBaseName(evt->parentName);
                std::string child = FeatureRegistry::GetBaseName(evt->processName);
                std::transform(parent.begin(), parent.end(), parent.begin(), ::tolower);
                std::transform(child.begin(), child.end(), child.begin(), ::tolower);
                if (parent.empty() || child.empty()) return 0.0f;
                if (parent == "winword.exe" && child == "powershell.exe") return 0.95f;
                if (parent == "outlook.exe" && child == "cmd.exe") return 0.95f;
                if (parent == "excel.exe" && child == "powershell.exe") return 0.95f;
                if (parent == "explorer.exe" || parent == "services.exe" || parent == "wininit.exe" || parent == "smss.exe") {
                    return 0.0f;
                }
                return 0.5f;
            }));

        // Feature 19: process_rarity_score
        RegisterExtractor(std::make_shared<LambdaExtractor>("process_rarity_score", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                std::string name = FeatureRegistry::GetBaseName(evt->processName);
                std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                const std::unordered_set<std::string> common = {
                    "svchost.exe", "explorer.exe", "cmd.exe", "powershell.exe",
                    "chrome.exe", "msedge.exe", "conhost.exe", "taskhostw.exe",
                    "services.exe", "lsass.exe", "winlogon.exe", "csrss.exe"
                };
                return common.count(name) ? 0.0f : 0.8f;
            }));

        // Feature 20: tree_fan_out_max
        RegisterExtractor(std::make_shared<LambdaExtractor>("tree_fan_out_max", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                return static_cast<float>(graph->GetMaxFanOut(pid));
            }));

        // Feature 21: lsass_access
        RegisterExtractor(std::make_shared<LambdaExtractor>("lsass_access", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                if (evt->eventType == "ProcessAccess") {
                    if (evt->fields.count("targetName")) {
                        try {
                            std::string tName = std::any_cast<std::string>(evt->fields.at("targetName"));
                            std::transform(tName.begin(), tName.end(), tName.begin(), ::tolower);
                            tName = FeatureRegistry::GetBaseName(tName);
                            if (tName == "lsass.exe") {
                                return 1.0f;
                            }
                        } catch (...) {}
                    }
                }
                return 0.0f;
            }));

        // Feature 22: access_rights_vm_read
        RegisterExtractor(std::make_shared<LambdaExtractor>("access_rights_vm_read", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                if (evt->eventType == "ProcessAccess") {
                    if (evt->fields.count("accessRights")) {
                        try {
                            uint32_t rights = std::any_cast<uint32_t>(evt->fields.at("accessRights"));
                            if ((rights & 0x0010) != 0) { // PROCESS_VM_READ is 0x0010
                                return 1.0f;
                            }
                        } catch (...) {}
                    }
                }
                return 0.0f;
            }));

        // Feature 23: persistence_key_access
        RegisterExtractor(std::make_shared<LambdaExtractor>("persistence_key_access", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                if (evt->eventType == "RegistrySet" || evt->eventType == "RegistryCreate") {
                    std::string keyPath = "";
                    if (evt->fields.count("keyPath")) {
                        try {
                            keyPath = std::any_cast<std::string>(evt->fields.at("keyPath"));
                        } catch (...) {}
                    }
                    std::transform(keyPath.begin(), keyPath.end(), keyPath.begin(), ::tolower);
                    if (keyPath.find("\\run") != std::string::npos ||
                        keyPath.find("\\runonce") != std::string::npos ||
                        keyPath.find("\\services\\") != std::string::npos) {
                        return 1.0f;
                    }
                }
                return 0.0f;
            }));

        // Feature 24: reg_sam_security_access
        RegisterExtractor(std::make_shared<LambdaExtractor>("reg_sam_security_access", 
            [](uint32_t pid, std::shared_ptr<NormalizedEvent> evt, std::shared_ptr<BehaviorGraph> graph, std::shared_ptr<SlidingWindowAggregator> windowAgg) {
                if (evt->eventType == "RegistrySet" || evt->eventType == "RegistryCreate") {
                    std::string keyPath = "";
                    if (evt->fields.count("keyPath")) {
                        try {
                            keyPath = std::any_cast<std::string>(evt->fields.at("keyPath"));
                        } catch (...) {}
                    }
                    std::transform(keyPath.begin(), keyPath.end(), keyPath.begin(), ::tolower);
                    if (keyPath.find("registry\\machine\\sam") != std::string::npos ||
                        keyPath.find("registry\\machine\\security") != std::string::npos) {
                        return 1.0f;
                    }
                }
                return 0.0f;
            }));

    }

public:
    FeatureRegistry() {
        RegisterBuiltinExtractors();
    }

    void RegisterExtractor(std::shared_ptr<IFeatureExtractor> extractor) {
        if (extractor) {
            m_extractors[extractor->GetName()] = extractor;
        }
    }

    bool LoadConfig(const std::string& configPath) {
        std::ifstream file(configPath);
        if (!file.is_open()) {
            std::cerr << "[FeatureRegistry] Failed to open features_config.json" << std::endl;
            return false;
        }

        nlohmann::json j;
        file >> j;

        m_activeFeatures.clear();
        for (const auto& item : j["features"]) {
            FeatureConfig cfg;
            cfg.index = item["index"];
            cfg.name = item["name"];
            cfg.type = item["type"];
            cfg.defaultValue = item["default"];
            cfg.namespaceName = item["namespace"];
            m_activeFeatures.push_back(cfg);
        }

        std::sort(m_activeFeatures.begin(), m_activeFeatures.end(), 
            [](const FeatureConfig& a, const FeatureConfig& b) {
                return a.index < b.index;
            }
        );

        std::cout << "[FeatureRegistry] Loaded " << m_activeFeatures.size() 
                  << " features from " << configPath << std::endl;
        return true;
    }

    bool LoadScalerParams(const std::string& scalerPath) {
        std::ifstream file(scalerPath);
        if (!file.is_open()) {
            std::cerr << "[FeatureRegistry] Failed to open " << scalerPath << std::endl;
            return false;
        }

        nlohmann::json j;
        file >> j;

        m_scalerParams.clear();
        for (auto& [key, val] : j.items()) {
            ScalerRange range;
            range.min = val["min"];
            range.max = val["max"];
            m_scalerParams[key] = range;
        }

        std::cout << "[FeatureRegistry] Loaded scaler parameters from " << scalerPath << std::endl;
        return true;
    }

    std::vector<float> Vectorize(uint32_t pid, std::shared_ptr<NormalizedEvent> evt,
                                 std::shared_ptr<BehaviorGraph> graph,
                                 std::shared_ptr<SlidingWindowAggregator> windowAgg) {
        // Populate missing event context dynamically from the behavior graph if available
        if (graph) {
            auto node = graph->GetNode(pid);
            if (node) {
                if (evt->processName.empty()) {
                    evt->processName = node->name;
                }
                if (evt->processPath.empty()) {
                    evt->processPath = node->path;
                }
                if (evt->parentName.empty() && node->ppid != 0) {
                    auto parentNode = graph->GetNode(node->ppid);
                    if (parentNode) {
                        evt->parentName = parentNode->name;
                    }
                }
            }
        }

        std::vector<float> featureVector;
        featureVector.reserve(m_activeFeatures.size());

        for (const auto& cfg : m_activeFeatures) {
            float val = cfg.defaultValue;
            auto it = m_extractors.find(cfg.name);
            if (it != m_extractors.end()) {
                val = it->second->Extract(pid, evt, graph, windowAgg);
            }

            // Normalization & Scaling
            if (val >= 0.0f) {
                if (cfg.type == "count" || cfg.type == "int" || cfg.type == "ordinal") {
                    val = std::log1p(val);
                    auto sIt = m_scalerParams.find(cfg.name);
                    if (sIt != m_scalerParams.end() && sIt->second.max > sIt->second.min) {
                        val = (val - sIt->second.min) / (sIt->second.max - sIt->second.min);
                    }
                    val = std::clamp(val, 0.0f, 1.0f);
                } else if (cfg.type == "float") {
                    auto sIt = m_scalerParams.find(cfg.name);
                    if (sIt != m_scalerParams.end() && sIt->second.max > sIt->second.min) {
                        val = (val - sIt->second.min) / (sIt->second.max - sIt->second.min);
                    }
                    val = std::clamp(val, 0.0f, 1.0f);
                }
            }

            featureVector.push_back(val);
        }
        return featureVector;
    }

    size_t GetFeatureCount() const {
        return m_activeFeatures.size();
    }
};
