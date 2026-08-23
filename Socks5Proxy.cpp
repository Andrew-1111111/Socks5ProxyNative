#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>

#include "config/NetworkConfiguration.h"
#include "config/ProxyConfiguration.h"
#include "friendly/FriendlyNameResolver.h"
#include "helper/NetworkMonitoring.h"
#include "server/ProxyServer.h"
#include "utils/Application.h"
#include "utils/Logger.h"

#include <atomic>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <exception>

#pragma comment(lib, "ws2_32.lib")

namespace {

std::atomic<bool> g_stop{false};

BOOL WINAPI ConsoleHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        Logger::Instance().Info("Shutdown signal received, stopping server...");
        g_stop = true;
        return TRUE;
    }
    return FALSE;
}

std::string GetExePath() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    return path;
}

std::string GetExeDir() {
    return std::filesystem::path(GetExePath()).parent_path().string();
}

}  // namespace

int main(int argc, char* argv[]) {
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 5;
    }

    int exitCode = 0;
    try {
        SingleInstanceGuard guard(L"Socks5Proxy_12345");
        if (guard.IsRunning()) {
            std::cout << "Another " << GetExePath() << " instance is already running." << std::endl;
            WSACleanup();
            return 1;
        }

        Logger::Instance().Info("SOCKS5 Proxy Server starting...");

        std::string configPath = "proxy.json";
        for (int i = 1; i < argc; ++i) {
            if (std::string(argv[i]) == "--config" && i + 1 < argc) {
                configPath = argv[++i];
            }
        }

        if (!std::filesystem::path(configPath).is_absolute()) {
            const auto local = std::filesystem::current_path() / configPath;
            if (std::filesystem::exists(local)) {
                configPath = local.string();
            } else {
                const auto besideExe = std::filesystem::path(GetExeDir()) / configPath;
                if (std::filesystem::exists(besideExe)) {
                    configPath = besideExe.string();
                }
            }
        }

        ProxyConfiguration proxyConfig;
        std::string error;
        if (!ProxyConfiguration::LoadFromFile(configPath, proxyConfig, error)) {
            Logger::Instance().Error(error);
            std::cout << "\nPress any key for exit...";
            std::cin.get();
            WSACleanup();
            return 4;
        }

        if (!proxyConfig.IsValid(error)) {
            Logger::Instance().Error("Invalid proxy configuration: {Error}", error);
            std::cout << "\nPress any key for exit...";
            std::cin.get();
            WSACleanup();
            return 2;
        }

        Logger::Instance().Info("Proxy configuration loaded successfully");

        if (!AdminLauncher::EnsureElevatedOrRelaunch()) {
            Logger::Instance().Error("Application requires administrator/root privileges to run.");
            WSACleanup();
            return 3;
        }

        const std::string exePath = GetExePath();
        const std::string ruleName = std::filesystem::path(exePath).stem().string();
        if (!WindowsFirewall::AllowApplication(exePath, ruleName)) {
            Logger::Instance().Error(
                "Failed to apply Windows Firewall rules for this application. "
                "The application may not work correctly without network access.");
        }

        FriendlyNameResolver resolver(proxyConfig.IPAddressMappings);
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

        NetworkMonitoring monitoring;
        std::thread monitorThread([&] {
            monitoring.Run(NetworkConfiguration::ListenIPAddress,
                           NetworkConfiguration::OutputInterfaceIP,
                           g_stop);
        });

        Logger::Instance().Info("Network monitoring: runned.");
        Logger::Instance().Info("Listen IP address: {Address}", NetworkConfiguration::ListenIPAddress);
        Logger::Instance().Info("Listen port: {Port}", NetworkConfiguration::ListenPort);
        Logger::Instance().Info("Output IP address: {Address}", NetworkConfiguration::OutputInterfaceIP);
        Logger::Instance().Info("DNS address: {Address}", NetworkConfiguration::DnsServer);
        Logger::Instance().Info("Starting SOCKS5 proxy server on: {Address}:{Port}",
                                NetworkConfiguration::ListenIPAddress,
                                NetworkConfiguration::ListenPort);

        ProxyServer server(resolver);
        server.Start(g_stop);

        g_stop = true;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }

        Logger::Instance().Info("SOCKS5 proxy server stopped gracefully.");
        exitCode = 0;
    } catch (const std::exception& ex) {
        Logger::Instance().Error("Fatal error occurred: {Error}", ex.what());
        exitCode = 5;
    }

    std::cout << "\nPress any key for exit...";
    std::cin.get();
    WSACleanup();
    return exitCode;
}
