#include "Network.h"

#include "../config/NetworkConfiguration.h"
#include "../dns/DnsResolver.h"
#include "Iocp.h"

#include <iphlpapi.h>
#include <IPTypes.h>
#include <ifdef.h>
#include <ipifcons.h>

#include <cctype>
#include <chrono>
#include <cstring>
#include <future>
#include <thread>

#pragma comment(lib, "iphlpapi.lib")

namespace {

bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (tolower(static_cast<unsigned char>(a[i])) != tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool NetworkUtils::ParseIP(const std::string& ip, sockaddr_storage& storage, int& family) {
    std::memset(&storage, 0, sizeof(storage));
    sockaddr_in* v4 = reinterpret_cast<sockaddr_in*>(&storage);
    if (inet_pton(AF_INET, ip.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        family = AF_INET;
        return true;
    }

    sockaddr_in6* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
    if (inet_pton(AF_INET6, ip.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        family = AF_INET6;
        return true;
    }
    return false;
}

std::string NetworkUtils::IPToString(const sockaddr* addr) {
    char buffer[INET6_ADDRSTRLEN]{};
    if (addr->sa_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, &v4->sin_addr, buffer, sizeof(buffer));
    } else if (addr->sa_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, &v6->sin6_addr, buffer, sizeof(buffer));
    }
    return buffer;
}

EndpointKey EndpointKey::From(const sockaddr_storage& ep) {
    EndpointKey key{};
    if (ep.ss_family == AF_INET) {
        key.len = sizeof(sockaddr_in);
    } else if (ep.ss_family == AF_INET6) {
        key.len = sizeof(sockaddr_in6);
    } else {
        return key;
    }
    key.addr = ep;
    return key;
}

bool EndpointKey::operator==(const EndpointKey& other) const {
    return len == other.len && len > 0 &&
           std::memcmp(&addr, &other.addr, static_cast<size_t>(len)) == 0;
}

size_t EndpointKeyHash::operator()(const EndpointKey& key) const noexcept {
    size_t hash = static_cast<size_t>(key.len);
    const auto* bytes = reinterpret_cast<const unsigned char*>(&key.addr);
    for (int i = 0; i < key.len; ++i) {
        hash = hash * 1315423911u + bytes[i];
    }
    return hash;
}

std::string NetworkUtils::EndpointToString(const sockaddr* addr) {
    if (!addr) return "Unknown";
    std::string ip = IPToString(addr);
    uint16_t port = 0;
    if (addr->sa_family == AF_INET) {
        port = ntohs(reinterpret_cast<const sockaddr_in*>(addr)->sin_port);
        return ip + ":" + std::to_string(port);
    }
    if (addr->sa_family == AF_INET6) {
        port = ntohs(reinterpret_cast<const sockaddr_in6*>(addr)->sin6_port);
        return "[" + ip + "]:" + std::to_string(port);
    }
    return "Unknown";
}

bool NetworkUtils::IsAnyAddress(const std::string& ip) {
    return ip == "0.0.0.0" || ip == "::" || ip.empty();
}

bool NetworkUtils::IsIPAddressAvailable(const std::string& ip) {
    if (IsAnyAddress(ip)) {
        return true;
    }

    sockaddr_storage storage{};
    int family = 0;
    if (!ParseIP(ip, storage, family)) {
        return false;
    }

    SOCKET sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    if (family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_port = 0;
        if (bind(sock, reinterpret_cast<sockaddr*>(v4), sizeof(sockaddr_in)) != 0) {
            closesocket(sock);
            return false;
        }
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_port = 0;
        if (IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr) && v6->sin6_scope_id == 0) {
            closesocket(sock);
            return false;
        }
        if (bind(sock, reinterpret_cast<sockaddr*>(v6), sizeof(sockaddr_in6)) != 0) {
            closesocket(sock);
            return false;
        }
    }

    closesocket(sock);
    return true;
}

bool NetworkUtils::IsIPv6Available(const std::string& ip) {
    sockaddr_storage storage{};
    int family = 0;
    if (!ParseIP(ip, storage, family) || family != AF_INET6) {
        return false;
    }
    return IsIPAddressAvailable(ip);
}

bool NetworkUtils::IsPortAvailable(uint16_t port) {
    auto probe = [port](int family) -> bool {
        SOCKET sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            return false;
        }
        BOOL reuse = TRUE;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

        if (family == AF_INET) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(port);
            const bool ok = bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
            closesocket(sock);
            return ok;
        }

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        const bool ok = bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
        closesocket(sock);
        return ok;
    };

    // Require free on both stacks when IPv6 is present; always require IPv4.
    if (!probe(AF_INET)) {
        return false;
    }
    SOCKET test6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (test6 != INVALID_SOCKET) {
        closesocket(test6);
        if (!probe(AF_INET6)) {
            return false;
        }
    }
    return true;
}

std::optional<std::string> NetworkUtils::GetIPAddressFromName(const std::string& interfaceName) {
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG size = 15000;
    std::vector<unsigned char> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
    }
    if (result != NO_ERROR) {
        return std::nullopt;
    }

    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) {
            continue;
        }

        char friendly[256]{};
        WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, friendly, sizeof(friendly), nullptr, nullptr);
        char description[256]{};
        WideCharToMultiByte(CP_UTF8, 0, adapter->Description, -1, description, sizeof(description), nullptr, nullptr);
        const char* adapterName = adapter->AdapterName ? adapter->AdapterName : "";

        if (!EqualsIgnoreCase(friendly, interfaceName) &&
            !EqualsIgnoreCase(description, interfaceName) &&
            !EqualsIgnoreCase(adapterName, interfaceName)) {
            continue;
        }

        std::optional<std::string> ipv4;
        std::optional<std::string> ipv6;
        for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            auto* sa = unicast->Address.lpSockaddr;
            if (!sa) continue;
            if (sa->sa_family == AF_INET && !ipv4) {
                ipv4 = IPToString(sa);
            } else if (sa->sa_family == AF_INET6 && !ipv6) {
                ipv6 = IPToString(sa);
            }
        }

        if (ipv4) return ipv4;
        if (ipv6) return ipv6;
        return std::nullopt;
    }

    return std::nullopt;
}

bool NetworkUtils::CheckDns(const std::string& dnsServer, const std::string& localBindIp,
                            int timeoutMs, int retries, int delayMs) {
    sockaddr_storage dnsStorage{};
    int dnsFamily = 0;
    if (!ParseIP(dnsServer, dnsStorage, dnsFamily)) {
        return false;
    }

    // Bind family comes from OutputInterfaceIP; localBindIp is the configured outbound.
    (void)localBindIp;

    const int prevTimeout = NetworkConfiguration::DnsReceiveTimeoutMs;
    if (timeoutMs > 0) {
        NetworkConfiguration::DnsReceiveTimeoutMs = timeoutMs;
    }

    IocpService iocp(2);
    if (!iocp.Start()) {
        NetworkConfiguration::DnsReceiveTimeoutMs = prevTimeout;
        return false;
    }

    auto resolver = std::make_shared<DnsResolver>(iocp, dnsServer);
    if (!resolver->Start()) {
        iocp.Stop();
        NetworkConfiguration::DnsReceiveTimeoutMs = prevTimeout;
        return false;
    }

    bool ok = false;
    for (int attempt = 1; attempt <= retries && !ok; ++attempt) {
        auto prom = std::make_shared<std::promise<bool>>();
        auto fut = prom->get_future();
        resolver->ResolveAsync(
            "google.com",
            [prom](std::optional<std::string> ip) {
                try {
                    prom->set_value(ip.has_value());
                } catch (...) {
                }
            },
            false);

        const auto waitBudget = std::chrono::milliseconds(
            (timeoutMs > 0 ? timeoutMs : 5000) + 1000);
        if (fut.wait_for(waitBudget) == std::future_status::ready) {
            ok = fut.get();
        } else {
            ok = false;
        }

        if (!ok && attempt < retries && delayMs > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    }

    resolver->Stop();
    iocp.Stop();
    NetworkConfiguration::DnsReceiveTimeoutMs = prevTimeout;
    return ok;
}

bool NetworkUtils::ResolveInterfaceName(const std::string& address, std::string& nameOut, bool& isUp) {
    nameOut.clear();
    isUp = false;

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG size = 15000;
    std::vector<unsigned char> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
    }
    if (result != NO_ERROR) {
        return false;
    }

    const bool any = IsAnyAddress(address);
    sockaddr_storage target{};
    int targetFamily = 0;
    if (!any && !ParseIP(address, target, targetFamily)) {
        return false;
    }

    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }

        char friendly[256]{};
        WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, friendly, sizeof(friendly), nullptr, nullptr);

        if (any) {
            nameOut = friendly;
            isUp = true;
            return true;
        }

        for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            auto* sa = unicast->Address.lpSockaddr;
            if (!sa || sa->sa_family != targetFamily) continue;
            if (IPToString(sa) == NetworkUtils::IPToString(reinterpret_cast<sockaddr*>(&target))) {
                nameOut = friendly;
                isUp = adapter->OperStatus == IfOperStatusUp;
                return true;
            }
        }
    }

    return false;
}
