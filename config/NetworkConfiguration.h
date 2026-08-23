#pragma once

#include <cstdint>
#include <string>

struct sockaddr_storage;

class NetworkConfiguration {
public:
    static std::string ListenIPAddress;
    static uint16_t ListenPort;
    static bool OutputIPv6Available;
    static std::string OutputInterfaceIP;
    static int OutputAddressFamily;  // AF_INET or AF_INET6
    static std::string DnsServer;
    static int MaxConnections;
    static std::string Username;
    static std::string Password;
    static bool EnableGssapi;
    static int GssapiMaxProtection;  // 1=integrity, 2=confidentiality, 3=selective

    static int IdleTimeoutMs;
    static int ConnectTimeoutMs;
    static int SendTimeoutMs;
    static int ReceiveTimeoutMs;
    static int DnsSendTimeoutMs;
    static int DnsReceiveTimeoutMs;
    static int UdpAssociateIdleTimeoutMs;
    static int SendBufferSize;
    static int ReceiveBufferSize;
    static bool NoDelay;
    static bool KeepAlive;
    static bool LingerEnabled;
    static int LingerTimeoutSec;
    static int TcpKeepAliveTime;
    static int TcpKeepAliveInterval;
    static int TcpKeepAliveRetryCount;
    static int BufferSize;

    static bool SetServerInterfaceIP(const std::string& ip, int port, std::string& errorMessage);
    static bool SetOutputInterfaceIP(const std::string& ip, std::string& errorMessage);
    static bool SetOutputInterfaceName(const std::string& interfaceName, std::string& errorMessage);
    static bool SetDnsIP(const std::string& ip, std::string& errorMessage);
    static bool SetMaxConnections(int connections, std::string& errorMessage);
    static bool SetUsernamePassword(const std::string& username, const std::string& password, std::string& errorMessage);
    /// Apply optional socket/buffer options (values < 0 leave current default).
    static bool SetSocketOptions(int idleTimeoutMs, int connectTimeoutMs,
                                 int sendTimeoutMs, int receiveTimeoutMs,
                                 int dnsSendTimeoutMs, int dnsReceiveTimeoutMs,
                                 int udpAssociateIdleTimeoutMs,
                                 int sendBufferSize, int receiveBufferSize, int bufferSize,
                                 int noDelay, int keepAlive,
                                 int lingerEnabled, int lingerTimeoutSec,
                                 int tcpKeepAliveTime, int tcpKeepAliveInterval, int tcpKeepAliveRetryCount,
                                 std::string& errorMessage);

    static bool HasCredentials();
    static bool FillListenAddress(sockaddr_storage& storage, int& length);
    static bool FillOutputBindAddress(sockaddr_storage& storage, int& length, uint16_t port = 0);
    static bool FillDnsEndpoint(sockaddr_storage& storage, int& length);
};
