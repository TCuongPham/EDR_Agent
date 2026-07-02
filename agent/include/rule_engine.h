// agent/include/rule_engine.h
#pragma once
#include <unordered_set>
#include <regex>
#include <string>
#include <memory>
#include <algorithm>
#include "normalized_event.h"

enum class RuleDecision : uint8_t {
    RuleDecisionClean = 0,
    RuleDecisionUnknown,
    RuleDecisionCritical
};

class RuleEngine {
private:
    std::unordered_set<std::string> m_whitelist;
    std::vector<std::regex> m_cmdlineRegex;

public:
    RuleEngine() {
        m_whitelist = {
            "system", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "taskhostw.exe", "searchindexer.exe"
        };
        m_cmdlineRegex = {
            std::regex("-[Ee]nc(odedCommand)?\\s+[A-Za-z0-9+/=]{100,}", std::regex_constants::icase),
            std::regex("-[Ee]xecution[Pp]olicy\\s+[Bb]ypass", std::regex_constants::icase),
            std::regex("(Invoke-WebRequest|IWR|WebClient|DownloadString|DownloadFile|curl|wget)", std::regex_constants::icase),
            std::regex("(procdump|minidump|lsass)", std::regex_constants::icase)
        };
    }

    RuleDecision Evaluate(std::shared_ptr<NormalizedEvent> evt) {
        // Lowercase name for whitelist comparison
        std::string procNameLower = evt->processName;
        std::transform(procNameLower.begin(), procNameLower.end(), procNameLower.begin(), ::tolower);
        
        // Strip path if present
        size_t lastSlash = procNameLower.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            procNameLower = procNameLower.substr(lastSlash + 1);
        }

        // Get and normalize path
        std::string pathLower = evt->processPath;
        std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);
        std::replace(pathLower.begin(), pathLower.end(), '/', '\\'); // standardize slashes

        // 1. Check Whitelist with path verification
        bool isWhitelisted = false;
        if (procNameLower == "system") {
            isWhitelisted = true; // NT Kernel
        } else if (procNameLower == "explorer.exe") {
            // explorer.exe must run from \windows\explorer.exe
            if (pathLower.size() >= 21 && pathLower.substr(pathLower.size() - 21) == "\\windows\\explorer.exe") {
                isWhitelisted = true;
            }
        } else if (m_whitelist.count(procNameLower)) {
            // Other standard processes must run from System32 folder
            std::string expectedSuffix = "\\windows\\system32\\" + procNameLower;
            if (pathLower.size() >= expectedSuffix.size() && 
                pathLower.substr(pathLower.size() - expectedSuffix.size()) == expectedSuffix) {
                isWhitelisted = true;
            }
        }

        if (isWhitelisted) {
            // Exceptions for whitelist: LSASS process access
            if (evt->eventType == "ProcessAccess" && evt->fields.count("targetName")) {
                try {
                    std::string target = std::any_cast<std::string>(evt->fields.at("targetName"));
                    std::transform(target.begin(), target.end(), target.begin(), ::tolower);
                    if (target.find("lsass") != std::string::npos) {
                        return RuleDecision::RuleDecisionCritical; // Accessing LSASS is critical
                    }
                } catch (...) {}
            }
            return RuleDecision::RuleDecisionClean;
        }

        // 2. Check cmdline regex for suspicious commands
        for (const auto& pattern : m_cmdlineRegex) {
            if (std::regex_search(evt->commandLine, pattern)) {
                return RuleDecision::RuleDecisionCritical;
            }
        }

        return RuleDecision::RuleDecisionUnknown;
    }
};
