#pragma once

#include "../../dns/DnsResolver.h"
#include "../../friendly/FriendlyNameResolver.h"
#include "../../network/Iocp.h"
#include "../../network/Network.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class UdpRelay : public IocpHandle {
public:
    using StopCallback = std::function<void()>;

    UdpRelay(IocpService& iocp,
             DnsResolver& dns,
             const sockaddr_storage& clientTcpEndPoint,
             const sockaddr_storage& clientTcpLocalEndPoint,
             FriendlyNameResolver& resolver,
             StopCallback onStopped = {});
    ~UdpRelay() override;

    bool Start();
    /// @param notifySession if true, invoke stop callback (idle timeout). False when session closes relay.
    void Stop(bool notifySession = true);
    /// Address:port to put in SOCKS5 BND (client-reachable).
    const sockaddr_storage& AdvertisedEndPoint() const { return advertisedEndPoint_; }
    const sockaddr_storage& LocalEndPoint() const { return localEndPoint_; }

    void OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) override;

private:
    struct PendingDomainPacket {
        std::vector<uint8_t> payload;
        uint16_t port = 0;
    };

    struct FragAssembly {
        sockaddr_storage destination{};
        bool hasIpDestination = false;
        std::string domain;
        uint16_t port = 0;
        std::map<uint8_t, std::vector<uint8_t>> parts;
        bool haveLast = false;
        uint8_t lastFragNum = 0;
        std::chrono::steady_clock::time_point updated{};
    };

    struct Outbound {
        std::vector<char> data;
        sockaddr_storage to{};
        int toLen = 0;
        IoContext ctx{IoOp::SendTo, 0};
    };

    struct DnsNotify {
        IoContext ctx{IoOp::User};
        std::string domain;
        std::optional<std::string> ip;
    };

    void HandlePacket(const uint8_t* data, int length, const sockaddr_storage& remote);
    void HandleClientPacket(const uint8_t* data, int length);
    void HandleServerResponse(const uint8_t* data, int length, const sockaddr_storage& source);
    void DispatchClientPayload(const sockaddr_storage* ipDestination,
                               const std::string* domain,
                               uint16_t port,
                               const uint8_t* payload,
                               int payloadLen);
    /// @return true if a complete datagram was assembled into outPayload
    bool ProcessFragment(uint8_t frag,
                         const std::string& assemblyKey,
                         const sockaddr_storage* ipDestination,
                         const std::string* domain,
                         uint16_t port,
                         const uint8_t* payload,
                         int payloadLen,
                         std::vector<uint8_t>& outPayload,
                         sockaddr_storage& outIpDestination,
                         bool& outHasIp,
                         std::string& outDomain,
                         uint16_t& outPort);
    void ForwardPayload(const uint8_t* payload, int payloadLen, const sockaddr_storage& destination);
    void EnqueueSend(std::vector<char> data, const sockaddr_storage& to);
    void EnqueueSendLocked(std::vector<char> data, const sockaddr_storage& to);
    void PumpSendLocked();
    void OnSendCompleted(IoContext* ctx);
    void OnDnsNotify(DnsNotify& notify);
    void CleanupState();
    bool PostNextRecv();
    bool BindRelaySocket();

    static constexpr size_t kMaxUdpSendsInFlight = 16;

    IocpService& iocp_;
    DnsResolver& dns_;
    FriendlyNameResolver& resolver_;
    StopCallback onStopped_;
    sockaddr_storage clientTcpEndPoint_{};
    sockaddr_storage clientTcpLocalEndPoint_{};
    sockaddr_storage localEndPoint_{};
    sockaddr_storage advertisedEndPoint_{};
    std::optional<sockaddr_storage> actualClientUdpEndPoint_;

    SOCKET udpSocket_ = INVALID_SOCKET;
    IoContext recvCtx_;
    std::atomic<bool> stop_{false};

    std::mutex stateMutex_;
    std::deque<std::unique_ptr<Outbound>> pendingSends_;
    std::list<std::unique_ptr<Outbound>> inFlightSends_;
    size_t sendsInFlight_ = 0;
    std::unordered_map<IoContext*, std::unique_ptr<DnsNotify>> dnsNotifies_;
    std::unordered_map<EndpointKey, std::chrono::steady_clock::time_point, EndpointKeyHash>
        activeDestinations_;
    std::unordered_map<std::string, std::deque<PendingDomainPacket>> pendingByDomain_;
    std::unordered_set<std::string> dnsInFlight_;
    std::unordered_map<std::string, FragAssembly> fragAssemblies_;
    std::chrono::steady_clock::time_point lastActivity_;
    std::chrono::steady_clock::time_point lastCleanup_;
};
