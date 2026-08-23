#pragma once

#include <atomic>
#include <string>
#include <thread>

class NetworkMonitoring {
public:
    void Run(const std::string& listenerAddress, const std::string& outputAddress, std::atomic<bool>& stopFlag);

private:
    bool ValidateInterface(const std::string& address, const char* tag);
    int currentNetworkCheck_ = 0;
    static constexpr int MaxNetworkCheckRetry = 3;
};
