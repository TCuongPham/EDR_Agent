// agent/src/collector/collector.cpp
#include "collector.h"
#include <iostream>
#include <objbase.h>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <winternl.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ole32.lib")

// Helper function to extract a property value as bytes
static bool GetPropertyData(PEVENT_RECORD pEvent, LPCWSTR propName, PBYTE buffer, DWORD &bufferSize)
{
    PROPERTY_DATA_DESCRIPTOR descriptor = {0};
    descriptor.PropertyName = (ULONGLONG)propName;
    descriptor.ArrayIndex = 0;

    TDHSTATUS status = TdhGetProperty(pEvent, 0, NULL, 1, &descriptor, bufferSize, buffer);
    return (status == ERROR_SUCCESS);
}

// Helper to get string property (converting wide string to ANSI)
static std::string GetStringProperty(PEVENT_RECORD pEvent, LPCWSTR propName)
{
    BYTE buffer[4096] = {0};
    DWORD size = sizeof(buffer);
    if (GetPropertyData(pEvent, propName, buffer, size))
    {
        std::wstring wstr((wchar_t *)buffer);
        if (wstr.empty())
            return "";
        int size_needed = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }
    return "";
}

// Helper to get DWORD property
static DWORD GetDWORDProperty(PEVENT_RECORD pEvent, LPCWSTR propName)
{
    DWORD val = 0;
    DWORD size = sizeof(DWORD);
    if (GetPropertyData(pEvent, propName, (PBYTE)&val, size))
    {
        return val;
    }
    return 0;
}

// Convert NT Device Path (e.g. \Device\HarddiskVolume4\...) to Drive Path (e.g. C:\...)
static std::string DevicePathToDrivePath(const std::string &devicePath)
{
    if (devicePath.empty())
        return "";

    static std::unordered_map<std::string, std::string> deviceMap;
    static bool initialized = false;

    if (!initialized)
    {
        wchar_t drive[] = L"A:";
        wchar_t device[512];
        for (char c = 'A'; c <= 'Z'; c++)
        {
            drive[0] = c;
            if (QueryDosDeviceW(drive, device, 512) != 0)
            {
                std::wstring wDevice(device);
                std::string sDevice(wDevice.begin(), wDevice.end());
                std::string sDrive(1, c);
                sDrive += ":";
                deviceMap[sDevice] = sDrive;
            }
        }
        initialized = true;
    }

    for (const auto &[device, drive] : deviceMap)
    {
        if (devicePath.size() >= device.size())
        {
            bool match = true;
            for (size_t i = 0; i < device.size(); i++)
            {
                if (tolower(devicePath[i]) != tolower(device[i]))
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return drive + devicePath.substr(device.size());
            }
        }
    }

    return devicePath;
}

// Query the command line dynamically from a running process using its PID
static std::string GetCommandLineFromPID(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        return "";
    }

    typedef NTSTATUS(NTAPI * pfnNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength);

    static pfnNtQueryInformationProcess NtQueryInformationProcess = nullptr;
    if (!NtQueryInformationProcess)
    {
        HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
        if (hNtDll)
        {
            NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        }
    }

    if (!NtQueryInformationProcess)
    {
        CloseHandle(hProcess);
        return "";
    }

    ULONG returnLength = 0;
    // ProcessCommandLineInformation is class 60
    NTSTATUS status = NtQueryInformationProcess(hProcess, 60, NULL, 0, &returnLength);
    if (status != 0xC0000004L && status != 0)
    {
        returnLength = 2048;
    }

    std::vector<BYTE> buffer(returnLength + 256, 0);
    status = NtQueryInformationProcess(hProcess, 60, buffer.data(), (ULONG)buffer.size(), &returnLength);

    std::string cmdLineStr = "";
    if (status == 0)
    {
        PUNICODE_STRING pCmdLine = (PUNICODE_STRING)buffer.data();
        if (pCmdLine->Length > 0 && pCmdLine->Buffer != nullptr)
        {
            PBYTE bufStart = buffer.data();
            PBYTE bufEnd = bufStart + buffer.size();
            PBYTE ptr = (PBYTE)pCmdLine->Buffer;
            if (ptr >= bufStart && ptr < bufEnd)
            {
                std::wstring wstr(pCmdLine->Buffer, pCmdLine->Length / sizeof(wchar_t));
                cmdLineStr = std::string(wstr.begin(), wstr.end());
            }
        }
    }

    CloseHandle(hProcess);
    return cmdLineStr;
}

void ETWConsumer::SetupProperties()
{
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (m_sessionName.length() + 1) * sizeof(wchar_t);
    m_properties = (EVENT_TRACE_PROPERTIES *)malloc(bufferSize);
    if (!m_properties)
        return;

    ZeroMemory(m_properties, bufferSize);
    m_properties->Wnode.BufferSize = bufferSize;
    m_properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    m_properties->Wnode.ClientContext = 1; // QPC time
    m_properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    m_properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    wcscpy_s((wchar_t *)((char *)m_properties + m_properties->LoggerNameOffset),
             m_sessionName.length() + 1, m_sessionName.c_str());
}

bool ETWConsumer::Start()
{
    if (m_isRunning)
        return true;

    SetupProperties();
    if (!m_properties)
        return false;

    ULONG status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), m_properties);
    if (status == ERROR_ALREADY_EXISTS)
    {
        ControlTraceW(0, m_sessionName.c_str(), m_properties, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), m_properties);
    }

    if (status != ERROR_SUCCESS)
    {
        std::cerr << "[ETWConsumer] StartTraceW failed: " << status << std::endl;
        free(m_properties);
        m_properties = nullptr;
        return false;
    }

    for (const auto &prov : m_providers)
    {
        GUID guid;
        if (CLSIDFromString(prov.first.c_str(), &guid) == NOERROR)
        {
            status = EnableTraceEx2(
                m_sessionHandle,
                &guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION,
                prov.second,
                0,
                0,
                NULL);
            if (status != ERROR_SUCCESS)
            {
                std::cerr << "[ETWConsumer] EnableTraceEx2 failed for " << prov.first.c_str() << ": " << status << std::endl;
            }
        }
    }

    m_isRunning = true;
    m_threadHandle = CreateThread(NULL, 0, TraceThreadStatic, this, 0, NULL);
    if (!m_threadHandle)
    {
        Stop();
        return false;
    }

    return true;
}

void ETWConsumer::Stop()
{
    if (!m_isRunning)
        return;
    m_isRunning = false;

    if (m_traceHandle != 0 && m_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(m_traceHandle);
        m_traceHandle = 0;
    }

    if (m_sessionHandle != 0 && m_properties)
    {
        ControlTraceW(m_sessionHandle, m_sessionName.c_str(), m_properties, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
    }

    if (m_threadHandle)
    {
        WaitForSingleObject(m_threadHandle, 5000);
        CloseHandle(m_threadHandle);
        m_threadHandle = nullptr;
    }

    if (m_properties)
    {
        free(m_properties);
        m_properties = nullptr;
    }
}

DWORD WINAPI ETWConsumer::TraceThreadStatic(LPVOID lpParam)
{
    ETWConsumer *pThis = static_cast<ETWConsumer *>(lpParam);
    pThis->RunTraceLoop();
    return 0;
}

void ETWConsumer::RunTraceLoop()
{
    EVENT_TRACE_LOGFILEW logFile = {0};
    logFile.LoggerName = (LPWSTR)m_sessionName.c_str();
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)EventRecordCallback;
    logFile.Context = this;

    m_traceHandle = OpenTraceW(&logFile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        std::cerr << "[ETWConsumer] OpenTraceW failed: " << GetLastError() << std::endl;
        return;
    }

    ULONG status = ProcessTrace(&m_traceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS)
    {
        std::cerr << "[ETWConsumer] ProcessTrace stopped: " << status << std::endl;
    }
}

void WINAPI ETWConsumer::EventRecordCallback(PEVENT_RECORD eventRecord)
{
    if (!eventRecord || !eventRecord->UserContext)
        return;

    ETWConsumer *pThis = static_cast<ETWConsumer *>(eventRecord->UserContext);
    USHORT eventId = eventRecord->EventHeader.EventDescriptor.Id;
    DWORD pid = eventRecord->EventHeader.ProcessId;
    DWORD tid = eventRecord->EventHeader.ThreadId;

    RawEvent raw = {0};
    raw.timestamp = eventRecord->EventHeader.TimeStamp.QuadPart;
    raw.pid = pid;
    raw.tid = tid;
    raw.sessionId = 1;

    // Core provider GUID definitions
    static const GUID processGuid =
        {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
    static const GUID fileGuid =
        {0xedd08927, 0x9cc4, 0x4e65, {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}};
    static const GUID networkGuid =
        {0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
    static const GUID registryGuid =
        {0x70eb4f03, 0xc1de, 0x4f73, {0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}};

    if (IsEqualGUID(eventRecord->EventHeader.ProviderId, processGuid))
    {
        if (eventId == 1)
        { // Process Start
            raw.eventType = EventType::EventProcessCreate;
            raw.pid = GetDWORDProperty(eventRecord, L"ProcessID");
            raw.ppid = GetDWORDProperty(eventRecord, L"ParentProcessID");

            // Get image name and translate NT Device path to drive path
            std::string image = GetStringProperty(eventRecord, L"ImageName");
            image = DevicePathToDrivePath(image);

            // Get command line from event; fallback to dynamic querying if not available
            std::string cmd = GetStringProperty(eventRecord, L"CommandLine");
            if (cmd.empty())
            {
                cmd = GetCommandLineFromPID(raw.pid);
                if (cmd.empty())
                {
                    cmd = image; // Fallback to image path if process ended quickly
                }
            }

            strcpy_s(raw.processName, image.c_str());
            strcpy_s(raw.commandLine, cmd.c_str());
            strcpy_s(raw.imagePath, image.c_str());
            pThis->m_callback(raw);
        }
        else if (eventId == 2)
        { // Process Stop
            raw.eventType = EventType::EventProcessTerminate;
            raw.pid = GetDWORDProperty(eventRecord, L"ProcessID");
            pThis->m_callback(raw);
        }
        else if (eventId == 9 || eventId == 10)
        { // OpenProcessHandle (9) / DuplicateProcessHandle (10) — Windows 10/11 Kernel-Process
            raw.eventType = EventType::EventProcessAccess;
            raw.targetPid = GetDWORDProperty(eventRecord, L"TargetProcessID");
            raw.accessRights = GetDWORDProperty(eventRecord, L"GrantedAccess");
            pThis->m_callback(raw);
        }
    }
    else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, fileGuid))
    {
        if (eventId == 64)
        { // File Create
            raw.eventType = EventType::EventFileCreate;
            std::string filename = GetStringProperty(eventRecord, L"FileName");
            filename = DevicePathToDrivePath(filename);
            strcpy_s(raw.filePath, filename.c_str());
            pThis->m_callback(raw);
        }
        else if (eventId == 69)
        { // File Delete
            raw.eventType = EventType::EventFileDelete;
            std::string filename = GetStringProperty(eventRecord, L"FileName");
            filename = DevicePathToDrivePath(filename);
            strcpy_s(raw.filePath, filename.c_str());
            pThis->m_callback(raw);
        }
    }
    else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, networkGuid))
    {
        if (eventId == 10)
        { // Connect
            raw.eventType = EventType::EventNetworkConnect;
            raw.protocol = 6;
            raw.srcPort = (uint16_t)GetDWORDProperty(eventRecord, L"sport");
            raw.dstPort = (uint16_t)GetDWORDProperty(eventRecord, L"dport");

            DWORD size = 16;
            PROPERTY_DATA_DESCRIPTOR descS = {0};
            descS.PropertyName = (ULONGLONG)L"saddr";
            TdhGetProperty(eventRecord, 0, NULL, 1, &descS, size, raw.srcIP);

            PROPERTY_DATA_DESCRIPTOR descD = {0};
            descD.PropertyName = (ULONGLONG)L"daddr";
            size = 16;
            TdhGetProperty(eventRecord, 0, NULL, 1, &descD, size, raw.dstIP);
            pThis->m_callback(raw);
        }
    }
    else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, registryGuid))
    {
        // Windows 10/11: Microsoft-Windows-Kernel-Registry Event IDs
        // CreateKey=12, OpenKey=13, DeleteKey=15, SetValueKey=14, DeleteValueKey=16
        if (eventId == 12)
        { // CreateKey — Windows 10/11
            raw.eventType = EventType::EventRegistryCreate;
            std::string key = GetStringProperty(eventRecord, L"RelativeName");
            strcpy_s(raw.regKeyPath, key.c_str());
            pThis->m_callback(raw);
        }
        else if (eventId == 14)
        { // SetValueKey — Windows 10/11
            raw.eventType = EventType::EventRegistrySet;
            std::string key = GetStringProperty(eventRecord, L"RelativeName");
            std::string valName = GetStringProperty(eventRecord, L"ValueName");
            strcpy_s(raw.regKeyPath, key.c_str());
            strcpy_s(raw.regValue, valName.c_str());
            pThis->m_callback(raw);
        }
        else if (eventId == 1 || eventId == 5)
        { // Fallback: legacy Event IDs for older Windows versions
            if (eventId == 1) {
                raw.eventType = EventType::EventRegistryCreate;
                std::string key = GetStringProperty(eventRecord, L"RelativeName");
                strcpy_s(raw.regKeyPath, key.c_str());
            } else {
                raw.eventType = EventType::EventRegistrySet;
                std::string key = GetStringProperty(eventRecord, L"RelativeName");
                std::string valName = GetStringProperty(eventRecord, L"ValueName");
                strcpy_s(raw.regKeyPath, key.c_str());
                strcpy_s(raw.regValue, valName.c_str());
            }
            pThis->m_callback(raw);
        }
    }
}
