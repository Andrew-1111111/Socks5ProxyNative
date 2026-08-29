#pragma once

#include <atomic>
#include <string>

class NetworkMonitoring {
public:
    void Run(const std::string& listenerAddress, const std::string& outputAddress, std::atomic<bool>& stopFlag);
    bool RestartRequested() const { return restartRequested_.load(std::memory_order_acquire); }

private:
    bool ValidateInterface(const std::string& address, const char* tag);
    int currentNetworkCheck_ = 0;
    std::atomic<bool> restartRequested_{false};
    static constexpr int MaxNetworkCheckRetry = 3;
};
