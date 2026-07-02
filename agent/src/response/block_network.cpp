// agent/src/response/block_network.cpp
#include "response.h"
#include <iostream>

void ResponseHandler::BlockNetworkForProcess(uint32_t pid) {
    // Simulated firewall/WFP action: Log block capability
    std::cout << "[ResponseHandler] [FIREWALL] Blocked all network connections for PID: " << pid << std::endl;
}
