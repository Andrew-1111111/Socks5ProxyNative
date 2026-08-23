#pragma once

#include <string>
#include <vector>

struct IPAddressMapping {
    std::string IPAddress;
    std::string FriendlyName;
};

class ProxyConfiguration {
public:
    std::string ListenIPAddress;
    int ListenPort = 1080;
    std::vector<std::string> OutputIPAddress;
    std::vector<std::string> OutputInterfaceName;
    std::string DnsServer;
    std::vector<IPAddressMapping> IPAddressMappings;
    int MaxConnections = 1000;
    int RunDelayS = 0;
    std::string Username;
    std::string Password;
    int EnableGssapi = -1;         // -1 unset, 0 false, 1 true
    int GssapiMaxProtection = -1;  // -1 unset; 1..3 per RFC 1961

    // Optional socket options (-1 = keep NetworkConfiguration default)
    int IdleTimeoutMs = -1;
    int ConnectTimeoutMs = -1;
    int SendTimeoutMs = -1;
    int ReceiveTimeoutMs = -1;
    int DnsSendTimeoutMs = -1;
    int DnsReceiveTimeoutMs = -1;
    int UdpAssociateIdleTimeoutMs = -1;
    int SendBufferSize = -1;
    int ReceiveBufferSize = -1;
    int BufferSize = -1;
    int NoDelay = -1;              // -1 unset, 0 false, 1 true
    int KeepAlive = -1;
    int LingerEnabled = -1;
    int LingerTimeoutSec = -1;
    int TcpKeepAliveTime = -1;
    int TcpKeepAliveInterval = -1;
    int TcpKeepAliveRetryCount = -1;

    static bool LoadFromFile(const std::string& path, ProxyConfiguration& config, std::string& errorMessage);
    bool IsValid(std::string& errorMessage) const;
};
