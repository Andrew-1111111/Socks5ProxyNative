#include "Application.h"

#include "../utils/Logger.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>

#include <filesystem>
#include <string>

namespace {

std::wstring CurrentCommandLineParameters() {
    const wchar_t* commandLine = GetCommandLineW();
    if (!commandLine) {
        return {};
    }

    const wchar_t* p = commandLine;
    if (*p == L'"') {
        ++p;
        while (*p && *p != L'"') {
            ++p;
        }
        if (*p == L'"') {
            ++p;
        }
    } else {
        while (*p && *p != L' ' && *p != L'\t') {
            ++p;
        }
    }
    while (*p == L' ' || *p == L'\t') {
        ++p;
    }
    return p;
}

}  // namespace

bool SingleInstanceGuard::TryAcquire() {
    SetLastError(ERROR_SUCCESS);
    HANDLE handle = CreateMutexW(nullptr, TRUE, mutexName_.c_str());
    if (!handle) {
        return false;
    }

    const DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS) {
        // Opened existing mutex owned by another process — we do not own it.
        CloseHandle(handle);
        return false;
    }

    mutex_ = handle;
    hasLock_ = true;
    isRunning_ = false;
    return true;
}

void SingleInstanceGuard::ReleaseHandle() {
    if (!mutex_) return;
    if (hasLock_) {
        ReleaseMutex(static_cast<HANDLE>(mutex_));
        hasLock_ = false;
    }
    CloseHandle(static_cast<HANDLE>(mutex_));
    mutex_ = nullptr;
}

SingleInstanceGuard::SingleInstanceGuard(const std::wstring& appId)
    : mutexName_(L"Global\\" + appId) {
    if (TryAcquire()) {
        return;
    }

    isRunning_ = true;
    hasLock_ = false;
}

SingleInstanceGuard::~SingleInstanceGuard() {
    ReleaseHandle();
}

bool AdminLauncher::IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        elevated = elevation.TokenIsElevated;
    }
    CloseHandle(token);
    return elevated == TRUE;
}

bool AdminLauncher::EnsureElevatedOrRelaunch() {
    if (IsElevated()) {
        return true;
    }

    wchar_t path[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        Logger::Instance().Warning("Failed to relaunch with elevated rights: cannot determine process path.");
        return false;
    }

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    const std::wstring parameters = CurrentCommandLineParameters();
    sei.lpParameters = parameters.empty() ? nullptr : parameters.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        Logger::Instance().Warning("Failed to relaunch with elevated rights.");
        return false;
    }

    if (sei.hProcess) {
        CloseHandle(sei.hProcess);
    }
    return false;
}

void AdminLauncher::RestartApplication(bool requestElevation) {
    wchar_t path[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        return;
    }

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = requestElevation ? L"runas" : L"open";
    sei.lpFile = path;
    const std::wstring parameters = CurrentCommandLineParameters();
    sei.lpParameters = parameters.empty() ? nullptr : parameters.c_str();
    sei.nShow = SW_SHOWNORMAL;
    ShellExecuteExW(&sei);
    ExitProcess(0);
}

bool WindowsFirewall::AllowApplication(const std::string& appPath, const std::string& ruleBaseName) {
    if (appPath.empty() || ruleBaseName.empty()) {
        return false;
    }
    if (!std::filesystem::exists(appPath)) {
        return false;
    }

    auto runNetsh = [](const std::string& args) -> bool {
        std::string command = "netsh advfirewall firewall " + args;
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::string mutableCmd = command;
        if (!CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            return false;
        }
        const DWORD waitResult = WaitForSingleObject(pi.hProcess, 15000);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
            WaitForSingleObject(pi.hProcess, 5000);
        }
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return code == 0;
    };

    const std::string inbound = ruleBaseName + " (Inbound)";
    const std::string outbound = ruleBaseName + " (Outbound)";

    runNetsh("delete rule name=\"" + inbound + "\"");
    runNetsh("delete rule name=\"" + outbound + "\"");

    const bool inOk = runNetsh("add rule name=\"" + inbound + "\" dir=in action=allow program=\"" + appPath + "\" enable=yes");
    const bool outOk = runNetsh("add rule name=\"" + outbound + "\" dir=out action=allow program=\"" + appPath + "\" enable=yes");
    return inOk && outOk;
}
