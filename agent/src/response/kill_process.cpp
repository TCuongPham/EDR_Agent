// agent/src/response/kill_process.cpp
#include "response.h"
#include <windows.h>
#include <iostream>

bool ResponseHandler::KillProcess(uint32_t pid) {
    std::cout << "[ResponseHandler] Attempting to terminate process (PID: " << pid << ")..." << std::endl;
    
    // Do not kill critical system processes or self (pid 0, 4, or current agent process)
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) {
        std::cerr << "[ResponseHandler] Refusing to kill critical system/agent process (PID: " << pid << ")" << std::endl;
        return false;
    }

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
