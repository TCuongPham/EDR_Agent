// agent/src/response/kill_process.cpp
#include "response.h"
#include <windows.h>
#include <iostream>

// Kich hoat SeDebugPrivilege de co the terminate cac tien trinh co quyen cao hon
// Can goi 1 lan truoc OpenProcess neu muon vuot qua rao can quyen (Error 5)
static bool EnableSeDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "[SeDebugPrivilege] OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        std::cerr << "[SeDebugPrivilege] LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "[SeDebugPrivilege] AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // AdjustTokenPrivileges tra ve TRUE ngay ca khi privilege khong duoc cap
    // Kiem tra GetLastError() de xac nhan
    bool success = (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    CloseHandle(hToken);

    if (!success) {
        std::cerr << "[SeDebugPrivilege] Could not enable SeDebugPrivilege (not in token). Run as SYSTEM or higher." << std::endl;
    }
    return success;
}

bool ResponseHandler::KillProcess(uint32_t pid) {
    std::cout << "[ResponseHandler] Attempting to terminate process (PID: " << pid << ")..." << std::endl;
    
    // Do not kill critical system processes or self (pid 0, 4, or current agent process)
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) {
        std::cerr << "[ResponseHandler] Refusing to kill critical system/agent process (PID: " << pid << ")" << std::endl;
        return false;
    }

    // Kich hoat SeDebugPrivilege de vuot qua rao can quyen (Error 5 / ACCESS_DENIED)
    // Can thiet khi terminate tien trinh co token Elevated cao hon Agent
    EnableSeDebugPrivilege();

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "[ResponseHandler] Error: OpenProcess failed for PID " << pid << ". Error: " << GetLastError() << std::endl;
        return false;
    }
    
    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    
    if (result) {
        std::cout << "[ResponseHandler] Success: Terminated process (PID: " << pid << ")" << std::endl;
        return true;
    } else {
        std::cerr << "[ResponseHandler] Error: TerminateProcess failed for PID " << pid << ". Error: " << GetLastError() << std::endl;
        return false;
    }
}
