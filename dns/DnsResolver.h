#pragma once

#include "DnsClient.h"
#include "../network/Iocp.h"

#include <atomic>
#include <cstddef>
#include <deque>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

/// Async DNS over IOCP (overlapped UDP + ConnectEx TCP fallback).
class DnsResolver : public IocpHandle {
public:
    using Callback = std::function<void(std::optional<std::string>)>;

    DnsResolver(IocpService& iocp, const std::string& dnsServer);
    ~DnsResolver() override;

    DnsResolver(const DnsResolver&) = delete;
    DnsResolver& operator=(const DnsResolver&) = delete;

    DnsClient& Client() { return client_; }

    bool Start();
    void Stop();

    /// Cache hit invokes callback on the caller thread; miss uses IOCP UDP/TCP.
    void ResolveAsync(std::string domain, Callback callback, bool useCache = true);

    void OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) override;

private:
    friend class TcpDnsQuery;

    struct PendingQuery {
        std::string domain;
        uint16_t txid = 0;
        uint16_t qtype = 1;
        bool tryAAAA = false;
        bool viaTcp = false;
        bool useCache = true;
        int udpAttempts = 0;
        std::vector<Callback> callbacks;
        IocpService::TimerId timerId = 0;
        std::shared_ptr<class TcpDnsQuery> tcp;
    };

    struct Outbound {
        std::vector<char> data;
        sockaddr_storage to{};
        int toLen = 0;
        IoContext ctx{IoOp::SendTo, 0};
    };

    static constexpr uint64_t kTimeoutKey = 1;
    static constexpr int kMaxUdpAttempts = 3;
    static constexpr size_t kMaxDnsSendsInFlight = 16;
    static constexpr size_t kMaxPendingSends = 4096;
    static constexpr size_t kMaxPendingQueries = 4096;
    static constexpr size_t kMaxCallbacksPerQuery = 256;

    uint16_t AllocTxidLocked();
    void BeginUdpQueryLocked(std::shared_ptr<PendingQuery> pending);
    void RetryUdpQueryLocked(std::shared_ptr<PendingQuery> pending);
    void EnqueueUdpSendLocked(std::vector<uint8_t> query);
    void PumpSendLocked();
    void OnUdpSendCompleted(IoContext* ctx);
    bool ArmTimerLocked(PendingQuery& pending);
    void CancelTimerLocked(PendingQuery& pending);
    void HandleUdpResponse(const uint8_t* data, int length, const sockaddr_storage& from);
    void OnQueryResult(uint16_t txid, const DnsClient::DnsResult& result, bool fromTcp, bool isTimeout = false);
    void FinishQuery(std::shared_ptr<PendingQuery> pending, const DnsClient::DnsResult& result);
    void StartTcpFallback(std::shared_ptr<PendingQuery> pending);
    bool FillDnsAddrFromServer();

    IocpService& iocp_;
    DnsClient client_;

    std::mutex mutex_;
    SOCKET udpSocket_ = INVALID_SOCKET;
    IoContext recvCtx_{IoOp::RecvFrom, 4096};
    std::deque<std::unique_ptr<Outbound>> pendingSends_;
    std::list<std::unique_ptr<Outbound>> inFlightSends_;
    size_t sendsInFlight_ = 0;
    bool recvPosted_ = false;

    sockaddr_storage dnsAddr_{};
    int dnsAddrLen_ = 0;

    std::unordered_map<uint16_t, std::shared_ptr<PendingQuery>> byId_;
    std::unordered_map<std::string, std::shared_ptr<PendingQuery>> byDomain_;
    std::atomic<uint32_t> idSeq_{1};
    std::atomic<bool> started_{false};
    std::atomic<bool> stopping_{false};
};
