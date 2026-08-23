#pragma once

#include <string>

class SingleInstanceGuard {
public:
    explicit SingleInstanceGuard(const std::wstring& appId);
    ~SingleInstanceGuard();

    SingleInstanceGuard(const SingleInstanceGuard&) = delete;
    SingleInstanceGuard& operator=(const SingleInstanceGuard&) = delete;

    /// True when another instance still holds the lock (this process must exit).
    bool IsRunning() const { return isRunning_; }

private:
    bool TryAcquire();
    void ReleaseHandle();
    static void CloseOtherSocks5Processes();

    std::wstring mutexName_;
    void* mutex_ = nullptr;
    bool hasLock_ = false;
    bool isRunning_ = false;
};

class AdminLauncher {
public:
    static bool EnsureElevatedOrRelaunch();
    static void RestartApplication(bool requestElevation = false);
    static bool IsElevated();
};

class WindowsFirewall {
public:
    static bool AllowApplication(const std::string& appPath, const std::string& ruleBaseName);
};
