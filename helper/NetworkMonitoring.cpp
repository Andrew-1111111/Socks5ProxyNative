#include "NetworkMonitoring.h"

#include "../network/Network.h"
#include "../utils/Logger.h"

#include <chrono>
#include <string_view>
#include <thread>

bool NetworkMonitoring::ValidateInterface(const std::string& address, const char* tag) {
    if (std::string_view(tag) == "Listener") {
        if (NetworkUtils::IsAnyAddress(address) || address == "127.0.0.1" || address == "::1") {
            return true;
        }
    }

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

bool NetworkMonitoring::CheckInterface(const std::string& address, const char* tag) {
    return ValidateInterface(address, tag);
}

void NetworkMonitoring::PrepareRestartAfterDelay(int delaySeconds, std::atomic<bool>& stopFlag) {
    if (delaySeconds <= 0) {
        restartRequested_.store(true, std::memory_order_release);
        return;
    }

    for (int remaining = delaySeconds; remaining > 0; --remaining) {
        if (stopFlag.load(std::memory_order_acquire)) {
            return;
        }
        Logger::Instance().Warning("Restarting application in {Remaining}s.", remaining);
        for (int i = 0; i < 10 && !stopFlag.load(std::memory_order_acquire); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    if (!stopFlag.load(std::memory_order_acquire)) {
        restartRequested_.store(true, std::memory_order_release);
    }
}

void NetworkMonitoring::Run(const std::string& listenerAddress, const std::string& outputAddress,
                            std::atomic<bool>& stopFlag) {
    while (!stopFlag.load(std::memory_order_acquire)) {
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
            Logger::Instance().Warning(
                "Network monitoring detected repeated interface failures; stopping for restart.");
            restartRequested_.store(true, std::memory_order_release);
            stopFlag.store(true, std::memory_order_release);
            return;
        }

        for (int i = 0; i < 50 && !stopFlag.load(std::memory_order_acquire); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}
