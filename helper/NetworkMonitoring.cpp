#include "NetworkMonitoring.h"

#include "../network/Network.h"
#include "../utils/Logger.h"

#include <chrono>
#include <atomic>
#include <string>
#include <thread>

bool NetworkMonitoring::ValidateInterface(const std::string& address, const char* tag) {
    std::string name;
    bool isUp = false;
    if (!NetworkUtils::ResolveInterfaceName(address, name, isUp)) {
        Logger::Instance().Error("{Tag} interface not found for IP: {IP}", tag, address);
        return false;
    }
    if (!isUp) {
        Logger::Instance().Error("{Tag} interface is not UP: {Name}", tag, name);
        return false;
    }
    return true;
}

void NetworkMonitoring::Run(const std::string& listenerAddress, const std::string& outputAddress,
                            std::atomic<bool>& stopFlag) {
    while (!stopFlag) {
        int allSuccess = 0;

        if (!ValidateInterface(listenerAddress, "Listener")) {
            ++currentNetworkCheck_;
        } else {
            ++allSuccess;
        }

        if (!ValidateInterface(outputAddress, "Output")) {
            ++currentNetworkCheck_;
        } else {
            ++allSuccess;
        }

        if (allSuccess >= 2) {
            currentNetworkCheck_ = 0;
        } else if (currentNetworkCheck_ >= MaxNetworkCheckRetry) {
            restartRequested_.store(true, std::memory_order_release);
            stopFlag.store(true, std::memory_order_release);
            return;
        }

        for (int i = 0; i < 50 && !stopFlag; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}
