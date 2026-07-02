// agent/include/collector.h
#pragma once
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>
#include <functional>
#include <vector>
#include <memory>
#include "common.h"

class ICollector {
public:
    virtual ~ICollector() = default;
    virtual bool Start() = 0;
    virtual void Stop() = 0;
    virtual std::string GetName() const = 0;
};

class ETWConsumer : public ICollector {
private:
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    EVENT_TRACE_PROPERTIES* m_properties = nullptr;
    std::wstring m_sessionName;
    std::string m_name;
    // List of Provider GUID string (e.g. "{22c607dd-8a81-40c0-b57e-dc0d05931d74}") and Keyword Mask
    std::vector<std::pair<std::wstring, uint64_t>> m_providers;
    std::function<void(const RawEvent&)> m_callback;
    bool m_isRunning = false;
    HANDLE m_threadHandle = nullptr;

    void SetupProperties();
    void RunTraceLoop();
    static DWORD WINAPI TraceThreadStatic(LPVOID lpParam);

public:
    ETWConsumer(const std::wstring& sessionName, const std::string& name, 
                const std::vector<std::pair<std::wstring, uint64_t>>& providers,
                std::function<void(const RawEvent&)> callback)
        : m_sessionName(sessionName), m_name(name), m_providers(providers), m_callback(callback) {}
    ~ETWConsumer() override { Stop(); }

    bool Start() override;
    void Stop() override;
    std::string GetName() const override { return m_name; }
    
    // Static Callback to receive events from Windows kernel
    static void WINAPI EventRecordCallback(PEVENT_RECORD eventRecord);
};
