#pragma once

#include "../../config/NetworkConfiguration.h"
#include "../../friendly/FriendlyNameResolver.h"
#include "../../network/Network.h"
#include "../../server/ProxyServer.h"
#include "../../server/protocol/Socks5Constants.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace integ {

inline void SetSocketTimeouts(SOCKET s, int ms) {
    DWORD timeout = static_cast<DWORD>(ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
}

inline uint16_t FindFreeTcpPort() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        throw std::runtime_error("socket failed");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        throw std::runtime_error("bind failed");
    }
    int len = sizeof(addr);
    getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    const uint16_t port = ntohs(addr.sin_port);
    closesocket(s);
    return port;
}

inline bool WaitForTcpAccept(uint16_t port, int timeoutMs = 5000) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            return false;
        }
        SetSocketTimeouts(s, 200);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        const int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        closesocket(s);
        if (rc == 0) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

inline bool SendAll(SOCKET s, const void* data, int len) {
    const char* p = static_cast<const char*>(data);
    int sent = 0;
    while (sent < len) {
        const int n = send(s, p + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

inline bool RecvExact(SOCKET s, void* data, int len) {
    char* p = static_cast<char*>(data);
    int got = 0;
    while (got < len) {
        const int n = recv(s, p + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

class TcpEchoServer {
public:
    TcpEchoServer() {
        listen_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_ == INVALID_SOCKET) {
            throw std::runtime_error("echo socket failed");
        }
        BOOL reuse = TRUE;
        setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(listen_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(listen_, 8) != 0) {
            closesocket(listen_);
            throw std::runtime_error("echo bind/listen failed");
        }
        int len = sizeof(addr);
        getsockname(listen_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        stop_.store(false);
        thread_ = std::thread([this] { Loop(); });
    }

    ~TcpEchoServer() {
        stop_.store(true);
        SOCKET wake = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (wake != INVALID_SOCKET) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port_);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            connect(wake, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            closesocket(wake);
        }
        closesocket(listen_);
        listen_ = INVALID_SOCKET;
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    uint16_t Port() const { return port_; }

private:
    void Loop() {
        while (!stop_.load()) {
            SOCKET client = accept(listen_, nullptr, nullptr);
            if (client == INVALID_SOCKET) {
                break;
            }
            if (stop_.load()) {
                closesocket(client);
                break;
            }
            std::thread([client] {
                char buf[2048];
                for (;;) {
                    const int n = recv(client, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    if (!SendAll(client, buf, n)) break;
                }
                closesocket(client);
            }).detach();
        }
    }

    SOCKET listen_ = INVALID_SOCKET;
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

struct NetworkConfigGuard {
    std::string listenIp = NetworkConfiguration::ListenIPAddress;
    uint16_t listenPort = NetworkConfiguration::ListenPort;
    std::string outputIp = NetworkConfiguration::OutputInterfaceIP;
    int outputFamily = NetworkConfiguration::OutputAddressFamily;
    std::string dns = NetworkConfiguration::DnsServer;
    int maxConn = NetworkConfiguration::MaxConnections;
    std::string user = NetworkConfiguration::Username;
    std::string pass = NetworkConfiguration::Password;
    bool gss = NetworkConfiguration::EnableGssapi;
    int idle = NetworkConfiguration::IdleTimeoutMs;
    int connect = NetworkConfiguration::ConnectTimeoutMs;
    int sendMs = NetworkConfiguration::SendTimeoutMs;
    int recvMs = NetworkConfiguration::ReceiveTimeoutMs;

    ~NetworkConfigGuard() {
        NetworkConfiguration::ListenIPAddress = listenIp;
        NetworkConfiguration::ListenPort = listenPort;
        NetworkConfiguration::OutputInterfaceIP = outputIp;
        NetworkConfiguration::OutputAddressFamily = outputFamily;
        NetworkConfiguration::DnsServer = dns;
        NetworkConfiguration::MaxConnections = maxConn;
        NetworkConfiguration::Username = user;
        NetworkConfiguration::Password = pass;
        NetworkConfiguration::EnableGssapi = gss;
        NetworkConfiguration::IdleTimeoutMs = idle;
        NetworkConfiguration::ConnectTimeoutMs = connect;
        NetworkConfiguration::SendTimeoutMs = sendMs;
        NetworkConfiguration::ReceiveTimeoutMs = recvMs;
    }
};

class ScopedProxy {
public:
    explicit ScopedProxy(uint16_t port,
                         int maxConnections = 0,
                         const std::string& username = {},
                         const std::string& password = {})
        : port_(port), resolver_({}) {
        NetworkConfiguration::ListenIPAddress = "127.0.0.1";
        NetworkConfiguration::ListenPort = port_;
        NetworkConfiguration::OutputInterfaceIP = "127.0.0.1";
        NetworkConfiguration::OutputAddressFamily = AF_INET;
        NetworkConfiguration::DnsServer = "8.8.8.8";
        NetworkConfiguration::MaxConnections = maxConnections;
        NetworkConfiguration::Username = username;
        NetworkConfiguration::Password = password;
        NetworkConfiguration::EnableGssapi = false;
        NetworkConfiguration::ConnectTimeoutMs = 2000;
        NetworkConfiguration::IdleTimeoutMs = 10000;
        NetworkConfiguration::SendTimeoutMs = 5000;
        NetworkConfiguration::ReceiveTimeoutMs = 5000;

        server_ = std::make_unique<ProxyServer>(resolver_);
        stop_.store(false);
        thread_ = std::thread([this] {
            try {
                server_->Start(stop_);
            } catch (...) {
                startFailed_.store(true);
            }
        });

        // When connection slots are limited, a readiness probe would consume a slot.
        bool ready = false;
        if (maxConnections > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
            ready = !startFailed_.load();
        } else {
            ready = WaitForTcpAccept(port_, 8000) && !startFailed_.load();
        }
        if (!ready) {
            Stop();
            throw std::runtime_error("proxy failed to start");
        }
    }

    ~ScopedProxy() { Stop(); }

    uint16_t Port() const { return port_; }

    void Stop() {
        stop_.store(true);
        if (server_) {
            server_->Stop();
        }
        if (thread_.joinable()) {
            thread_.join();
        }
        server_.reset();
    }

private:
    uint16_t port_ = 0;
    FriendlyNameResolver resolver_;
    std::unique_ptr<ProxyServer> server_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> startFailed_{false};
    std::thread thread_;
};

inline SOCKET ConnectTcp(const char* ip, uint16_t port, int timeoutMs = 5000) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    SetSocketTimeouts(s, timeoutMs);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

inline bool Socks5HandshakeNoAuth(SOCKET s) {
    const uint8_t req[] = {0x05, 0x01, 0x00};
    uint8_t resp[2]{};
    return SendAll(s, req, sizeof(req)) && RecvExact(s, resp, 2) &&
           resp[0] == 0x05 && resp[1] == 0x00;
}

inline bool Socks5HandshakeUserPass(SOCKET s) {
    const uint8_t req[] = {0x05, 0x01, 0x02};
    uint8_t resp[2]{};
    return SendAll(s, req, sizeof(req)) && RecvExact(s, resp, 2) &&
           resp[0] == 0x05 && resp[1] == 0x02;
}

inline bool Socks5UserPassAuth(SOCKET s, const std::string& user, const std::string& pass) {
    std::vector<uint8_t> req;
    req.push_back(0x01);
    req.push_back(static_cast<uint8_t>(user.size()));
    req.insert(req.end(), user.begin(), user.end());
    req.push_back(static_cast<uint8_t>(pass.size()));
    req.insert(req.end(), pass.begin(), pass.end());
    uint8_t resp[2]{};
    return SendAll(s, req.data(), static_cast<int>(req.size())) && RecvExact(s, resp, 2) &&
           resp[0] == 0x01 && resp[1] == 0x00;
}

inline bool Socks5ConnectIpv4(SOCKET s, const char* ipv4, uint16_t port, uint8_t& replyCode) {
    uint8_t req[10]{};
    req[0] = 0x05;
    req[1] = socks5::Command::Connect;
    req[2] = 0x00;
    req[3] = socks5::AddressType::IPv4;
    inet_pton(AF_INET, ipv4, req + 4);
    req[8] = static_cast<uint8_t>((port >> 8) & 0xFF);
    req[9] = static_cast<uint8_t>(port & 0xFF);
    if (!SendAll(s, req, sizeof(req))) {
        return false;
    }
    uint8_t resp[10]{};
    if (!RecvExact(s, resp, 10)) {
        return false;
    }
    replyCode = resp[1];
    return resp[0] == 0x05 && resp[3] == socks5::AddressType::IPv4;
}

inline bool Socks5UdpAssociate(SOCKET s, uint8_t& replyCode, sockaddr_storage& relayOut, int& relayLen) {
    uint8_t req[10]{};
    req[0] = 0x05;
    req[1] = socks5::Command::UdpAssociate;
    req[2] = 0x00;
    req[3] = socks5::AddressType::IPv4;
    // DST = 0.0.0.0:0
    if (!SendAll(s, req, sizeof(req))) {
        return false;
    }
    uint8_t resp[10]{};
    if (!RecvExact(s, resp, 10)) {
        return false;
    }
    replyCode = resp[1];
    if (resp[0] != 0x05 || resp[3] != socks5::AddressType::IPv4) {
        return false;
    }
    std::memset(&relayOut, 0, sizeof(relayOut));
    auto* v4 = reinterpret_cast<sockaddr_in*>(&relayOut);
    v4->sin_family = AF_INET;
    std::memcpy(&v4->sin_addr, resp + 4, 4);
    const uint16_t portHost = static_cast<uint16_t>((resp[8] << 8) | resp[9]);
    v4->sin_port = htons(portHost);
    relayLen = sizeof(sockaddr_in);
    return true;
}

class UdpEchoServer {
public:
    UdpEchoServer() {
        sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_ == INVALID_SOCKET) {
            throw std::runtime_error("udp echo socket failed");
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            closesocket(sock_);
            throw std::runtime_error("udp echo bind failed");
        }
        int len = sizeof(addr);
        getsockname(sock_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        stop_.store(false);
        thread_ = std::thread([this] { Loop(); });
    }

    ~UdpEchoServer() {
        stop_.store(true);
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    uint16_t Port() const { return port_; }

private:
    void Loop() {
        char buf[2048];
        while (!stop_.load()) {
            sockaddr_storage from{};
            int fromLen = sizeof(from);
            const int n = recvfrom(sock_, buf, sizeof(buf), 0,
                                   reinterpret_cast<sockaddr*>(&from), &fromLen);
            if (n <= 0) break;
            sendto(sock_, buf, n, 0, reinterpret_cast<sockaddr*>(&from), fromLen);
        }
    }

    SOCKET sock_ = INVALID_SOCKET;
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

inline std::vector<uint8_t> BuildSocksUdpIpv4Request(const char* ipv4, uint16_t port,
                                                     const void* payload, size_t payloadLen) {
    std::vector<uint8_t> packet;
    packet.push_back(0);
    packet.push_back(0);
    packet.push_back(0);  // FRAG standalone
    packet.push_back(socks5::AddressType::IPv4);
    uint8_t ip[4]{};
    inet_pton(AF_INET, ipv4, ip);
    packet.insert(packet.end(), ip, ip + 4);
    packet.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(port & 0xFF));
    const auto* p = static_cast<const uint8_t*>(payload);
    packet.insert(packet.end(), p, p + payloadLen);
    return packet;
}

inline bool ParseSocksUdpIpv4Reply(const uint8_t* data, int len, std::string& payloadOut) {
    if (len < 10) return false;
    if (data[0] != 0 || data[1] != 0 || data[2] != 0) return false;
    if (data[3] != socks5::AddressType::IPv4) return false;
    payloadOut.assign(reinterpret_cast<const char*>(data + 10),
                      static_cast<size_t>(len - 10));
    return true;
}

}  // namespace integ
