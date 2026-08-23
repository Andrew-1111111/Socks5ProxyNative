#include "NetworkConfiguration.h"

#include "../network/Network.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <string>

std::string NetworkConfiguration::ListenIPAddress = "127.0.0.1";
uint16_t NetworkConfiguration::ListenPort = 1080;
bool NetworkConfiguration::OutputIPv6Available = false;
std::string NetworkConfiguration::OutputInterfaceIP = "0.0.0.0";
int NetworkConfiguration::OutputAddressFamily = AF_INET;
std::string NetworkConfiguration::DnsServer = "8.8.8.8";
int NetworkConfiguration::MaxConnections = 1000;
std::string NetworkConfiguration::Username;
std::string NetworkConfiguration::Password;
bool NetworkConfiguration::EnableGssapi = false;
int NetworkConfiguration::GssapiMaxProtection = 1;

int NetworkConfiguration::IdleTimeoutMs = 60'000;
int NetworkConfiguration::ConnectTimeoutMs = 30'000;
int NetworkConfiguration::SendTimeoutMs = 30'000;
int NetworkConfiguration::ReceiveTimeoutMs = 30'000;
int NetworkConfiguration::DnsSendTimeoutMs = 5'000;
int NetworkConfiguration::DnsReceiveTimeoutMs = 5'000;
int NetworkConfiguration::UdpAssociateIdleTimeoutMs = 120'000;
int NetworkConfiguration::SendBufferSize = 256 * 1024;
int NetworkConfiguration::ReceiveBufferSize = 256 * 1024;
bool NetworkConfiguration::NoDelay = true;
bool NetworkConfiguration::KeepAlive = true;
bool NetworkConfiguration::LingerEnabled = false;
int NetworkConfiguration::LingerTimeoutSec = 0;
int NetworkConfiguration::TcpKeepAliveTime = 60;
int NetworkConfiguration::TcpKeepAliveInterval = 10;
int NetworkConfiguration::TcpKeepAliveRetryCount = 5;
int NetworkConfiguration::BufferSize = 80 * 1024;

bool NetworkConfiguration::SetServerInterfaceIP(const std::string& ip, int port, std::string& errorMessage) {
    errorMessage.clear();
    if (ip.empty()) {
        errorMessage = "The IP address cannot be null or empty.";
        return false;
    }

    sockaddr_storage storage{};
    int family = 0;
    if (!NetworkUtils::ParseIP(ip, storage, family)) {
        errorMessage = "'" + ip + "' is not a valid IP address.";
        return false;
    }

    if (!NetworkUtils::IsIPAddressAvailable(ip)) {
        errorMessage = "The IP address " + ip + " is not available for binding.";
        return false;
    }

    if (port < 0 || port > 65535) {
        errorMessage = "The port must be in the range 0-65535.";
        return false;
    }

    if (!NetworkUtils::IsPortAvailable(static_cast<uint16_t>(port))) {
        errorMessage = "The port " + std::to_string(port) + " is already in use.";
        return false;
    }

    ListenIPAddress = ip;
    ListenPort = static_cast<uint16_t>(port);
    return true;
}

bool NetworkConfiguration::SetOutputInterfaceIP(const std::string& ip, std::string& errorMessage) {
    errorMessage.clear();
    if (ip.empty()) {
        errorMessage = "The interface IP cannot be null or empty.";
        return false;
    }

    sockaddr_storage storage{};
    int family = 0;
    if (!NetworkUtils::ParseIP(ip, storage, family)) {
        errorMessage = "'" + ip + "' is not a valid IP address.";
        return false;
    }

    if (!NetworkUtils::IsIPAddressAvailable(ip)) {
        errorMessage = "The IP address " + ip + " is not available for binding.";
        return false;
    }

    OutputInterfaceIP = ip;
    OutputAddressFamily = family;
    OutputIPv6Available = (family == AF_INET6) && NetworkUtils::IsIPv6Available(ip);
    return true;
}

bool NetworkConfiguration::SetOutputInterfaceName(const std::string& interfaceName, std::string& errorMessage) {
    errorMessage.clear();
    if (interfaceName.empty()) {
        errorMessage = "The network interface name cannot be null or empty.";
        return false;
    }

    auto address = NetworkUtils::GetIPAddressFromName(interfaceName);
    if (!address) {
        errorMessage = "The interface '" + interfaceName + "' is not valid or not found.";
        return false;
    }

    return SetOutputInterfaceIP(*address, errorMessage);
}

bool NetworkConfiguration::SetDnsIP(const std::string& ip, std::string& errorMessage) {
    errorMessage.clear();
    if (ip.empty()) {
        errorMessage = "The DNS server address cannot be null or empty.";
        return false;
    }

    sockaddr_storage storage{};
    int family = 0;
    if (!NetworkUtils::ParseIP(ip, storage, family)) {
        errorMessage = "'" + ip + "' is not a valid IP address.";
        return false;
    }

    if (!NetworkUtils::CheckDns(ip, OutputInterfaceIP)) {
        errorMessage = "The DNS server '" + ip + "' is unreachable or not responding.";
        return false;
    }

    DnsServer = ip;
    return true;
}

bool NetworkConfiguration::SetMaxConnections(int connections, std::string& errorMessage) {
    errorMessage.clear();
    if (connections < 0 || connections > 1048576) {
        errorMessage = "The number of connections must be in the range 0-1048576.";
        return false;
    }
    MaxConnections = connections;
    return true;
}

bool NetworkConfiguration::SetUsernamePassword(const std::string& username, const std::string& password,
                                               std::string& errorMessage) {
    errorMessage.clear();
    if (username.empty() || password.empty()) {
        errorMessage = "Username and password cannot be empty.";
        return false;
    }
    if (username.size() > 255 || password.size() > 255) {
        errorMessage = "Username/password exceeds maximum allowed length of 255 bytes.";
        return false;
    }

    Username = username;
    Password = password;
    return true;
}

bool NetworkConfiguration::SetSocketOptions(int idleTimeoutMs, int connectTimeoutMs,
                                            int sendTimeoutMs, int receiveTimeoutMs,
                                            int dnsSendTimeoutMs, int dnsReceiveTimeoutMs,
                                            int udpAssociateIdleTimeoutMs,
                                            int sendBufferSize, int receiveBufferSize, int bufferSize,
                                            int noDelay, int keepAlive,
                                            int lingerEnabled, int lingerTimeoutSec,
                                            int tcpKeepAliveTime, int tcpKeepAliveInterval,
                                            int tcpKeepAliveRetryCount,
                                            std::string& errorMessage) {
    errorMessage.clear();
    auto requireNonNeg = [&](int v, const char* name) {
        if (v < 0) {
            errorMessage = std::string(name) + " must be >= 0.";
            return false;
        }
        return true;
    };
    auto requirePos = [&](int v, const char* name) {
        if (v <= 0) {
            errorMessage = std::string(name) + " must be > 0.";
            return false;
        }
        return true;
    };
    auto requireMax = [&](int v, int maximum, const char* name) {
        if (v > maximum) {
            errorMessage = std::string(name) + " exceeds the supported maximum.";
            return false;
        }
        return true;
    };

    if (idleTimeoutMs >= 0) {
        if (!requireNonNeg(idleTimeoutMs, "IdleTimeoutMs") ||
            !requireMax(idleTimeoutMs, 86'400'000, "IdleTimeoutMs")) return false;
        IdleTimeoutMs = idleTimeoutMs;
    }
    if (connectTimeoutMs >= 0) {
        if (!requirePos(connectTimeoutMs, "ConnectTimeoutMs") ||
            !requireMax(connectTimeoutMs, 86'400'000, "ConnectTimeoutMs")) return false;
        ConnectTimeoutMs = connectTimeoutMs;
    }
    if (sendTimeoutMs >= 0) {
        if (!requireNonNeg(sendTimeoutMs, "SendTimeoutMs") ||
            !requireMax(sendTimeoutMs, 86'400'000, "SendTimeoutMs")) return false;
        SendTimeoutMs = sendTimeoutMs;
    }
    if (receiveTimeoutMs >= 0) {
        if (!requireNonNeg(receiveTimeoutMs, "ReceiveTimeoutMs") ||
            !requireMax(receiveTimeoutMs, 86'400'000, "ReceiveTimeoutMs")) return false;
        ReceiveTimeoutMs = receiveTimeoutMs;
    }
    if (dnsSendTimeoutMs >= 0) {
        if (!requirePos(dnsSendTimeoutMs, "DnsSendTimeoutMs") ||
            !requireMax(dnsSendTimeoutMs, 86'400'000, "DnsSendTimeoutMs")) return false;
        DnsSendTimeoutMs = dnsSendTimeoutMs;
    }
    if (dnsReceiveTimeoutMs >= 0) {
        if (!requirePos(dnsReceiveTimeoutMs, "DnsReceiveTimeoutMs") ||
            !requireMax(dnsReceiveTimeoutMs, 86'400'000, "DnsReceiveTimeoutMs")) return false;
        DnsReceiveTimeoutMs = dnsReceiveTimeoutMs;
    }
    if (udpAssociateIdleTimeoutMs >= 0) {
        if (!requirePos(udpAssociateIdleTimeoutMs, "UdpAssociateIdleTimeoutMs") ||
            !requireMax(udpAssociateIdleTimeoutMs, 86'400'000, "UdpAssociateIdleTimeoutMs")) return false;
        UdpAssociateIdleTimeoutMs = udpAssociateIdleTimeoutMs;
    }
    if (sendBufferSize >= 0) {
        if (!requirePos(sendBufferSize, "SendBufferSize") ||
            !requireMax(sendBufferSize, 16 * 1024 * 1024, "SendBufferSize")) return false;
        SendBufferSize = sendBufferSize;
    }
    if (receiveBufferSize >= 0) {
        if (!requirePos(receiveBufferSize, "ReceiveBufferSize") ||
            !requireMax(receiveBufferSize, 16 * 1024 * 1024, "ReceiveBufferSize")) return false;
        ReceiveBufferSize = receiveBufferSize;
    }
    if (bufferSize >= 0) {
        if (!requirePos(bufferSize, "BufferSize") ||
            !requireMax(bufferSize, 16 * 1024 * 1024, "BufferSize")) return false;
        BufferSize = bufferSize;
    }
    if (noDelay >= 0) NoDelay = noDelay != 0;
    if (keepAlive >= 0) KeepAlive = keepAlive != 0;
    if (lingerEnabled >= 0) LingerEnabled = lingerEnabled != 0;
    if (lingerTimeoutSec >= 0) {
        if (!requireNonNeg(lingerTimeoutSec, "LingerTimeoutSec") ||
            !requireMax(lingerTimeoutSec, 65535, "LingerTimeoutSec")) return false;
        LingerTimeoutSec = lingerTimeoutSec;
    }
    if (tcpKeepAliveTime >= 0) {
        if (!requirePos(tcpKeepAliveTime, "TcpKeepAliveTime") ||
            !requireMax(tcpKeepAliveTime, 4'294'967, "TcpKeepAliveTime")) return false;
        TcpKeepAliveTime = tcpKeepAliveTime;
    }
    if (tcpKeepAliveInterval >= 0) {
        if (!requirePos(tcpKeepAliveInterval, "TcpKeepAliveInterval") ||
            !requireMax(tcpKeepAliveInterval, 4'294'967, "TcpKeepAliveInterval")) return false;
        TcpKeepAliveInterval = tcpKeepAliveInterval;
    }
    if (tcpKeepAliveRetryCount >= 0) {
        if (!requirePos(tcpKeepAliveRetryCount, "TcpKeepAliveRetryCount") ||
            !requireMax(tcpKeepAliveRetryCount, 255, "TcpKeepAliveRetryCount")) return false;
        TcpKeepAliveRetryCount = tcpKeepAliveRetryCount;
    }
    return true;
}

bool NetworkConfiguration::HasCredentials() {
    return !Username.empty() && !Password.empty();
}

bool NetworkConfiguration::FillListenAddress(sockaddr_storage& storage, int& length) {
    std::memset(&storage, 0, sizeof(storage));
    int family = 0;
    if (!NetworkUtils::ParseIP(ListenIPAddress, storage, family)) {
        return false;
    }
    if (family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_port = htons(ListenPort);
        length = sizeof(sockaddr_in);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_port = htons(ListenPort);
        length = sizeof(sockaddr_in6);
    }
    return true;
}

bool NetworkConfiguration::FillOutputBindAddress(sockaddr_storage& storage, int& length, uint16_t port) {
    std::memset(&storage, 0, sizeof(storage));
    int family = 0;
    if (!NetworkUtils::ParseIP(OutputInterfaceIP, storage, family)) {
        return false;
    }
    if (family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_port = htons(port);
        length = sizeof(sockaddr_in);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_port = htons(port);
        length = sizeof(sockaddr_in6);
    }
    return true;
}

bool NetworkConfiguration::FillDnsEndpoint(sockaddr_storage& storage, int& length) {
    std::memset(&storage, 0, sizeof(storage));
    int family = 0;
    if (!NetworkUtils::ParseIP(DnsServer, storage, family)) {
        return false;
    }
    if (family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_port = htons(53);
        length = sizeof(sockaddr_in);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_port = htons(53);
        length = sizeof(sockaddr_in6);
    }
    return true;
}
