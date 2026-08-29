#include "DnsResolver.h"

#include "../config/NetworkConfiguration.h"
#include "../network/Network.h"
#include "../utils/Logger.h"

#include <cctype>
#include <cstring>
#include <stdexcept>

namespace {

std::string ToLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool SameEndpoint(const sockaddr_storage& lhs, const sockaddr_storage& rhs) {
    if (lhs.ss_family != rhs.ss_family) {
        return false;
    }
    if (lhs.ss_family == AF_INET) {
        const auto* a = reinterpret_cast<const sockaddr_in*>(&lhs);
        const auto* b = reinterpret_cast<const sockaddr_in*>(&rhs);
        return a->sin_port == b->sin_port &&
               a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    if (lhs.ss_family == AF_INET6) {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(&lhs);
        const auto* b = reinterpret_cast<const sockaddr_in6*>(&rhs);
        return a->sin6_port == b->sin6_port &&
               std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0 &&
               a->sin6_scope_id == b->sin6_scope_id;
    }
    return false;
}

}  // namespace

class TcpDnsQuery : public IocpHandle {
public:
    enum class Phase : uint8_t { Connect, Send, RecvLen, RecvBody };

    TcpDnsQuery(DnsResolver& parent, uint16_t txid, uint16_t qtype, std::vector<uint8_t> query)
        : parent_(parent), txid_(txid), qtype_(qtype), query_(std::move(query)),
          connectCtx_(IoOp::Connect),
          sendCtx_(IoOp::Send, 0),
          recvCtx_(IoOp::Recv, 65536) {}

    ~TcpDnsQuery() override {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

    void Cancel() {
        std::lock_guard completionLock(completionMutex_);
        std::lock_guard lock(stateMutex_);
        done_ = true;
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

    bool Start() {
        std::lock_guard lock(stateMutex_);
        if (done_) {
            return false;
        }

        sockaddr_storage bindAddr{};
        int bindLen = 0;
        if (!NetworkConfiguration::FillOutputBindAddress(bindAddr, bindLen)) {
            return false;
        }

        socket_ = IocpService::CreateTcpSocket(bindAddr.ss_family);
        if (socket_ == INVALID_SOCKET) {
            return false;
        }

        BOOL nodelay = NetworkConfiguration::NoDelay ? TRUE : FALSE;
        setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
        if (NetworkConfiguration::DnsSendTimeoutMs > 0) {
            DWORD ms = static_cast<DWORD>(NetworkConfiguration::DnsSendTimeoutMs);
            setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
        }
        if (NetworkConfiguration::DnsReceiveTimeoutMs > 0) {
            DWORD ms = static_cast<DWORD>(NetworkConfiguration::DnsReceiveTimeoutMs);
            setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
        }

        if (bind(socket_, reinterpret_cast<sockaddr*>(&bindAddr), bindLen) != 0) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
            return false;
        }

        if (!parent_.iocp_.Associate(socket_, shared_from_this())) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
            return false;
        }

        phase_ = Phase::Connect;
        return parent_.iocp_.PostConnect(socket_, &connectCtx_,
                                         reinterpret_cast<sockaddr*>(&parent_.dnsAddr_),
                                         parent_.dnsAddrLen_, shared_from_this());
    }

    void OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) override {
        std::lock_guard lock(stateMutex_);
        if (done_) return;

        if (error != 0) {
            Fail();
            return;
        }

        switch (phase_) {
        case Phase::Connect: {
            sendCtx_.buffer.resize(2 + query_.size());
            sendCtx_.buffer[0] = static_cast<char>((query_.size() >> 8) & 0xFF);
            sendCtx_.buffer[1] = static_cast<char>(query_.size() & 0xFF);
            std::memcpy(sendCtx_.buffer.data() + 2, query_.data(), query_.size());
            phase_ = Phase::Send;
            if (!parent_.iocp_.PostSend(socket_, &sendCtx_, 0, sendCtx_.buffer.size(), shared_from_this())) {
                Fail();
            }
            break;
        }
        case Phase::Send: {
            if (bytes < sendCtx_.sendLength) {
                const size_t next = sendCtx_.sendOffset + bytes;
                const size_t left = sendCtx_.sendLength - bytes;
                if (!parent_.iocp_.PostSend(socket_, &sendCtx_, next, left, shared_from_this())) {
                    Fail();
                }
                return;
            }
            recvNeed_ = 2;
            recvGot_ = 0;
            phase_ = Phase::RecvLen;
            if (!parent_.iocp_.PostRecv(socket_, &recvCtx_, shared_from_this())) {
                Fail();
            }
            break;
        }
        case Phase::RecvLen:
        case Phase::RecvBody: {
            if (bytes == 0) {
                Fail();
                return;
            }
            recvGot_ += bytes;
            if (!ContinueRecv()) {
                Fail();
            }
            break;
        }
        }
        (void)ctx;
    }

private:
    bool PostRecvMore() {
        if (recvNeed_ <= recvGot_) {
            return true;
        }
        if (recvCtx_.buffer.size() < recvNeed_) {
            recvCtx_.buffer.resize(recvNeed_);
        }
        return parent_.iocp_.PostRecv(socket_, &recvCtx_, shared_from_this(),
                                      recvGot_, recvNeed_ - recvGot_);
    }

    bool ContinueRecv() {
        if (phase_ == Phase::RecvLen) {
            if (recvGot_ < 2) {
                return PostRecvMore();
            }
            const auto* p = reinterpret_cast<const uint8_t*>(recvCtx_.buffer.data());
            const int length = (p[0] << 8) | p[1];
            if (length <= 0 || length > 65535) {
                return false;
            }
            recvNeed_ = static_cast<size_t>(2 + length);
            phase_ = Phase::RecvBody;
        }

        if (recvGot_ < recvNeed_) {
            return PostRecvMore();
        }
        CompleteBody();
        return true;
    }

    void CompleteBody() {
        done_ = true;
        const auto* p = reinterpret_cast<const uint8_t*>(recvCtx_.buffer.data());
        const int length = (p[0] << 8) | p[1];
        auto result = DnsClient::ParseResponse(p + 2, length, txid_, qtype_);
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
        parent_.OnQueryResult(txid_, result, true);
    }

    void Fail() {
        if (done_) return;
        done_ = true;
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
        parent_.OnQueryResult(txid_, DnsClient::DnsResult::Invalid(), true);
    }

    DnsResolver& parent_;
    uint16_t txid_ = 0;
    uint16_t qtype_ = 1;
    std::vector<uint8_t> query_;
    SOCKET socket_ = INVALID_SOCKET;
    Phase phase_ = Phase::Connect;
    IoContext connectCtx_;
    IoContext sendCtx_;
    IoContext recvCtx_;
    size_t recvNeed_ = 0;
    size_t recvGot_ = 0;
    bool done_ = false;
    std::mutex stateMutex_;
};

DnsResolver::DnsResolver(IocpService& iocp, const std::string& dnsServer)
    : iocp_(iocp), client_(dnsServer) {}

DnsResolver::~DnsResolver() {
    Stop();
}

bool DnsResolver::FillDnsAddrFromServer() {
    int family = 0;
    if (!NetworkUtils::ParseIP(client_.Server(), dnsAddr_, family)) {
        return false;
    }
    if (family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(&dnsAddr_)->sin_port = htons(53);
        dnsAddrLen_ = sizeof(sockaddr_in);
    } else if (family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(&dnsAddr_)->sin6_port = htons(53);
        dnsAddrLen_ = sizeof(sockaddr_in6);
    } else {
        return false;
    }
    return true;
}

bool DnsResolver::Start() {
    if (started_.exchange(true)) {
        return true;
    }
    stopping_ = false;

    if (!FillDnsAddrFromServer()) {
        started_ = false;
        return false;
    }

    sockaddr_storage bindAddr{};
    int bindLen = 0;
    if (!NetworkConfiguration::FillOutputBindAddress(bindAddr, bindLen)) {
        started_ = false;
        return false;
    }

    // DNS server family must match outbound bind family.
    if (bindAddr.ss_family != dnsAddr_.ss_family) {
        started_ = false;
        return false;
    }

    udpSocket_ = IocpService::CreateUdpSocket(bindAddr.ss_family);
    if (udpSocket_ == INVALID_SOCKET) {
        started_ = false;
        return false;
    }

    if (bind(udpSocket_, reinterpret_cast<sockaddr*>(&bindAddr), bindLen) != 0) {
        closesocket(udpSocket_);
        udpSocket_ = INVALID_SOCKET;
        started_ = false;
        return false;
    }

    if (!iocp_.Associate(udpSocket_, shared_from_this())) {
        closesocket(udpSocket_);
        udpSocket_ = INVALID_SOCKET;
        started_ = false;
        return false;
    }

    recvPosted_ = false;
    if (!iocp_.PostRecvFrom(udpSocket_, &recvCtx_, shared_from_this())) {
        closesocket(udpSocket_);
        udpSocket_ = INVALID_SOCKET;
        started_ = false;
        return false;
    }
    recvPosted_ = true;
    return true;
}

void DnsResolver::Stop() {
    std::unique_lock completionLock(completionMutex_);
    if (!started_) {
        return;
    }
    stopping_ = true;

    std::vector<std::shared_ptr<PendingQuery>> pending;
    {
        std::lock_guard lock(mutex_);
        for (auto& [id, q] : byId_) {
            CancelTimerLocked(*q);
            pending.push_back(q);
        }
        byId_.clear();
        byDomain_.clear();
        pendingSends_.clear();
    }

    std::vector<std::shared_ptr<TcpDnsQuery>> tcpPins;
    for (auto& q : pending) {
        for (Callback& cb : q->callbacks) {
            if (cb) cb(std::nullopt);
        }
        q->callbacks.clear();
        if (q->tcp) {
            tcpPins.push_back(q->tcp);
        }
        q->tcp.reset();
    }

    if (udpSocket_ != INVALID_SOCKET) {
        closesocket(udpSocket_);
        udpSocket_ = INVALID_SOCKET;
    }

    completionLock.unlock();

    for (auto& t : tcpPins) {
        if (t) {
            t->Cancel();
        }
    }

    for (auto& t : tcpPins) {
        if (t) {
            t->WaitPendingZero(-1);
        }
    }
    WaitPendingZero(-1);
    started_ = false;
}

void DnsResolver::ResolveAsync(std::string domainRaw, Callback callback, bool useCache) {
    if (!callback) return;

    if (domainRaw.empty() || stopping_ || !started_) {
        callback(std::nullopt);
        return;
    }

    const std::string domain = ToLower(std::move(domainRaw));

    if (useCache) {
        if (auto cached = client_.TryGetCached(domain)) {
            callback(*cached);
            return;
        }
    }

    std::lock_guard lock(mutex_);
    if (stopping_ || !started_) {
        callback(std::nullopt);
        return;
    }

    if (auto it = byDomain_.find(domain); it != byDomain_.end()) {
        if (it->second->callbacks.size() >= kMaxCallbacksPerQuery) {
            callback(std::nullopt);
            return;
        }
        it->second->useCache = it->second->useCache && useCache;
        it->second->callbacks.push_back(std::move(callback));
        return;
    }
    if (byDomain_.size() >= kMaxPendingQueries) {
        callback(std::nullopt);
        return;
    }

    auto pending = std::make_shared<PendingQuery>();
    pending->domain = domain;
    pending->txid = AllocTxidLocked();
    pending->qtype = 1; // A
    pending->tryAAAA = NetworkConfiguration::OutputIPv6Available;
    pending->useCache = useCache;
    pending->callbacks.push_back(std::move(callback));

    byId_[pending->txid] = pending;
    byDomain_[domain] = pending;
    BeginUdpQueryLocked(pending);
}

uint16_t DnsResolver::AllocTxidLocked() {
    for (int i = 0; i < 10000; ++i) {
        const uint16_t id = DnsClient::GenerateId();
        if (id == 0) continue;
        if (byId_.find(id) == byId_.end()) {
            return id;
        }
    }
    for (;;) {
        const uint16_t id = static_cast<uint16_t>(idSeq_.fetch_add(1));
        if (id != 0 && byId_.find(id) == byId_.end()) {
            return id;
        }
    }
}

void DnsResolver::BeginUdpQueryLocked(std::shared_ptr<PendingQuery> pending) {
    pending->viaTcp = false;
    ++pending->udpAttempts;
    try {
        auto query = DnsClient::BuildQuery(pending->domain, pending->txid, pending->qtype);
        if (!ArmTimerLocked(*pending)) {
            throw std::runtime_error("Failed to schedule DNS timeout");
        }
        EnqueueUdpSendLocked(std::move(query));
    } catch (...) {
        byId_.erase(pending->txid);
        byDomain_.erase(pending->domain);
        std::vector<Callback> cbs = std::move(pending->callbacks);
        for (Callback& cb : cbs) {
            if (cb) cb(std::nullopt);
        }
    }
}

void DnsResolver::RetryUdpQueryLocked(std::shared_ptr<PendingQuery> pending) {
    byId_.erase(pending->txid);
    pending->txid = AllocTxidLocked();
    pending->tcp.reset();
    byId_[pending->txid] = pending;
    BeginUdpQueryLocked(pending);
}

void DnsResolver::EnqueueUdpSendLocked(std::vector<uint8_t> query) {
    if (udpSocket_ == INVALID_SOCKET || pendingSends_.size() >= kMaxPendingSends) {
        return;
    }
    std::unique_ptr<Outbound> out = std::make_unique<Outbound>();
    out->data.assign(reinterpret_cast<const char*>(query.data()),
                     reinterpret_cast<const char*>(query.data()) + query.size());
    out->to = dnsAddr_;
    out->toLen = dnsAddrLen_;
    pendingSends_.push_back(std::move(out));
    PumpSendLocked();
}

void DnsResolver::PumpSendLocked() {
    while (sendsInFlight_ < kMaxDnsSendsInFlight && !pendingSends_.empty() &&
           udpSocket_ != INVALID_SOCKET && !stopping_) {
        std::unique_ptr<Outbound> out = std::move(pendingSends_.front());
        pendingSends_.pop_front();
        Outbound* raw = out.get();
        if (!iocp_.PostSendTo(udpSocket_, &raw->ctx, raw->data.data(), raw->data.size(),
                              reinterpret_cast<sockaddr*>(&raw->to), raw->toLen, shared_from_this())) {
            pendingSends_.push_front(std::move(out));
            Logger::Instance().Warning("Failed to post DNS UDP send; waiting for retry.");
            break;
        }
        inFlightSends_.push_back(std::move(out));
        ++sendsInFlight_;
    }
}

void DnsResolver::OnUdpSendCompleted(IoContext* ctx) {
    std::lock_guard lock(mutex_);
    bool found = false;
    for (auto it = inFlightSends_.begin(); it != inFlightSends_.end(); ++it) {
        if (&(*it)->ctx == ctx) {
            inFlightSends_.erase(it);
            found = true;
            break;
        }
    }
    if (!found) {
        Logger::Instance().Warning("Unexpected DNS UDP send completion context");
        return;
    }
    if (sendsInFlight_ > 0) {
        --sendsInFlight_;
    }
    if (!stopping_) {
        PumpSendLocked();
    }
}

bool DnsResolver::ArmTimerLocked(PendingQuery& pending) {
    CancelTimerLocked(pending);
    const int timeoutMs = NetworkConfiguration::DnsReceiveTimeoutMs > 0
                              ? NetworkConfiguration::DnsReceiveTimeoutMs
                              : 3000;
    pending.timerId = iocp_.ScheduleTimeout(shared_from_this(), (kTimeoutKey << 32) | pending.txid, timeoutMs);
    return pending.timerId != 0;
}

void DnsResolver::CancelTimerLocked(PendingQuery& pending) {
    if (pending.timerId != 0) {
        iocp_.CancelTimeout(pending.timerId);
        pending.timerId = 0;
    }
}

void DnsResolver::HandleUdpResponse(const uint8_t* data, int length, const sockaddr_storage& from) {
    if (length < 12) {
        return;
    }

    if (!SameEndpoint(from, dnsAddr_)) {
        return;
    }

    const uint16_t txid = static_cast<uint16_t>((data[0] << 8) | data[1]);
    std::shared_ptr<PendingQuery> pending;
    {
        std::lock_guard lock(mutex_);
        auto it = byId_.find(txid);
        if (it == byId_.end() || it->second->viaTcp) {
            return;
        }
        pending = it->second;
    }

    auto result = DnsClient::ParseResponse(data, length, pending->txid, pending->qtype);
    if (!result.fromNetwork) {
        return;
    }
    OnQueryResult(txid, result, false);
}

void DnsResolver::OnQueryResult(uint16_t txid, const DnsClient::DnsResult& result, bool fromTcp, bool isTimeout) {
    std::lock_guard completionLock(completionMutex_);
    std::shared_ptr<PendingQuery> pending;
    {
        std::lock_guard lock(mutex_);
        auto it = byId_.find(txid);
        if (it == byId_.end()) {
            return;
        }
        pending = it->second;
        // Ignore late UDP after TCP fallback started (timeouts still apply).
        if (!fromTcp && !isTimeout && pending->viaTcp) {
            return;
        }
        CancelTimerLocked(*pending);
    }

    // UDP timeout / hard I/O miss: retry UDP, then TCP (not only on TC bit).
    if (isTimeout && !fromTcp && !pending->viaTcp) {
        if (pending->udpAttempts < kMaxUdpAttempts) {
            Logger::Instance().Debug(
                "DNS UDP timeout for {Domain}, retry {Attempt}/{Max}.",
                pending->domain, pending->udpAttempts + 1, kMaxUdpAttempts);
            std::lock_guard lock(mutex_);
            if (byId_.find(txid) == byId_.end()) {
                return;
            }
            RetryUdpQueryLocked(pending);
            return;
        }
        Logger::Instance().Debug(
            "DNS UDP exhausted for {Domain}, trying TCP.",
            pending->domain);
        StartTcpFallback(pending);
        return;
    }

    if (!fromTcp && result.truncated) {
        // Prefer an address already present in the UDP answer; TCP only when needed.
        if (result.address) {
            FinishQuery(pending, result);
            return;
        }
        StartTcpFallback(pending);
        return;
    }

    // Real DNS answer with no A: optionally try AAAA. Do not treat timeouts as "no A".
    if (result.fromNetwork && !result.address && pending->tryAAAA && pending->qtype == 1 && !result.truncated) {
        std::lock_guard lock(mutex_);
        if (byId_.find(txid) == byId_.end()) {
            return;
        }
        byId_.erase(txid);
        pending->qtype = 28;
        pending->txid = AllocTxidLocked();
        pending->tryAAAA = false;
        pending->udpAttempts = 0;
        pending->tcp.reset();
        byId_[pending->txid] = pending;
        BeginUdpQueryLocked(pending);
        return;
    }

    FinishQuery(pending, result);
}

void DnsResolver::OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) {
    if (!ctx) return;

    if (ctx->op == IoOp::User) {
        const uint64_t key = ctx->userKey;
        if ((key >> 32) == kTimeoutKey) {
            const uint16_t txid = static_cast<uint16_t>(key & 0xFFFF);
            OnQueryResult(txid, DnsClient::DnsResult::Invalid(), false, true);
        }
        return;
    }

    if (ctx->op == IoOp::SendTo) {
        OnUdpSendCompleted(ctx);
        return;
    }

    if (ctx->op == IoOp::RecvFrom) {
        recvPosted_ = false;
        if (!stopping_ && error == 0 && bytes > 0) {
            HandleUdpResponse(reinterpret_cast<const uint8_t*>(ctx->buffer.data()),
                              static_cast<int>(bytes), ctx->addr);
        }

        if (!stopping_ && udpSocket_ != INVALID_SOCKET) {
            if (iocp_.PostRecvFrom(udpSocket_, &recvCtx_, shared_from_this())) {
                recvPosted_ = true;
            } else {
                Logger::Instance().Error(
                    "Failed to repost DNS UDP receive; falling back to TCP for pending queries.");
                closesocket(udpSocket_);
                udpSocket_ = INVALID_SOCKET;
                std::vector<std::shared_ptr<PendingQuery>> fallback;
                {
                    std::lock_guard lock(mutex_);
                    pendingSends_.clear();
                    for (const auto& [txid, pending] : byId_) {
                        (void)txid;
                        if (pending && !pending->viaTcp) {
                            fallback.push_back(pending);
                        }
                    }
                }
                for (const auto& pending : fallback) {
                    StartTcpFallback(pending);
                }
            }
        }
        return;
    }

    (void)error;
}

void DnsResolver::StartTcpFallback(std::shared_ptr<PendingQuery> pending) {
    std::vector<uint8_t> query;
    try {
        query = DnsClient::BuildQuery(pending->domain, pending->txid, pending->qtype);
    } catch (...) {
        FinishQuery(pending, DnsClient::DnsResult::Invalid());
        return;
    }

    bool timerArmed = false;
    {
        std::lock_guard lock(mutex_);
        pending->viaTcp = true;
        timerArmed = ArmTimerLocked(*pending);
    }
    if (!timerArmed) {
        FinishQuery(pending, DnsClient::DnsResult::Invalid());
        return;
    }

    auto tcp = std::make_shared<TcpDnsQuery>(*this, pending->txid, pending->qtype, std::move(query));
    {
        std::lock_guard lock(mutex_);
        pending->tcp = tcp;
    }

    if (!tcp->Start()) {
        FinishQuery(pending, DnsClient::DnsResult::Invalid());
    }
}

void DnsResolver::FinishQuery(std::shared_ptr<PendingQuery> pending, const DnsClient::DnsResult& result) {
    std::vector<Callback> callbacks;
    const bool useCache = pending->useCache;
    {
        std::lock_guard lock(mutex_);
        CancelTimerLocked(*pending);
        byId_.erase(pending->txid);
        byDomain_.erase(pending->domain);
        pending->tcp.reset();
        callbacks = std::move(pending->callbacks);
    }

    if (!result.address) {
        if (!result.fromNetwork) {
            Logger::Instance().Warning(
                "DNS lookup failed for {Domain} (timeout or I/O error, type={Type}).",
                pending->domain, static_cast<int>(pending->qtype));
        } else if (result.truncated) {
            Logger::Instance().Warning(
                "DNS lookup failed for {Domain} (truncated response, TCP fallback failed, type={Type}).",
                pending->domain, static_cast<int>(pending->qtype));
        } else {
            Logger::Instance().Warning(
                "DNS lookup failed for {Domain} (no matching records, type={Type}).",
                pending->domain, static_cast<int>(pending->qtype));
        }
    }

    if (useCache) {
        client_.Cache(pending->domain, result);
    }
    for (Callback& cb : callbacks) {
        if (cb) cb(result.address);
    }
}
