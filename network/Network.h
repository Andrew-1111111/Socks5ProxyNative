#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

struct EndpointKey {
    sockaddr_storage addr{};
    int len = 0;

    static EndpointKey From(const sockaddr_storage& ep);
    bool operator==(const EndpointKey& other) const;
};

struct EndpointKeyHash {
    size_t operator()(const EndpointKey& key) const noexcept;
};

class NetworkUtils {
public:
    static bool IsIPAddressAvailable(const std::string& ip);
    static bool IsIPv6Available(const std::string& ip);
    static bool IsPortAvailable(uint16_t port);
    static std::optional<std::string> GetIPAddressFromName(const std::string& interfaceName);
    static bool CheckDns(const std::string& dnsServer, const std::string& localBindIp,
                         int timeoutMs = 5000, int retries = 2, int delayMs = 200);

    static bool ParseIP(const std::string& ip, sockaddr_storage& storage, int& family);
    static std::string IPToString(const sockaddr* addr);
    static std::string EndpointToString(const sockaddr* addr);
    static bool ResolveInterfaceName(const std::string& address, std::string& nameOut, bool& isUp);
    static bool IsAnyAddress(const std::string& ip);
};
