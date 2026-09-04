#pragma once

#include <atomic>
#include <string>

class NetworkMonitoring {
public:
    static constexpr int StartupRestartDelaySec = 30;

    void Run(const std::string& listenerAddress, const std::string& outputAddress, std::atomic<bool>& stopFlag);
    bool RestartRequested() const { return restartRequested_.load(std::memory_order_acquire); }

    /// Waits delaySeconds unless stopFlag is set, then marks restart as requested.
    void PrepareRestartAfterDelay(int delaySeconds, std::atomic<bool>& stopFlag);

    /// Checks whether an interface for the address is usable (Listener allows any/loopback).
    bool CheckInterface(const std::string& address, const char* tag);

private:
    bool ValidateInterface(const std::string& address, const char* tag);

    int currentNetworkCheck_ = 0;
    std::atomic<bool> restartRequested_{false};
    static constexpr int MaxNetworkCheckRetry = 3;
};
