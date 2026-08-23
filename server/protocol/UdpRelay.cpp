#include "UdpRelay.h"

#include "Socks5Constants.h"
#include "../../config/NetworkConfiguration.h"
#include "../../network/Network.h"
#include "../../utils/Logger.h"

#include <WinSock2.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {
constexpr auto kCleanupInterval = std::chrono::seconds(10);
constexpr auto kFragReassemblyTimeout = std::chrono::seconds(5);
constexpr size_t kMaxAssembledUdpPayload = 65535;
}

std::chrono::milliseconds UdpIdleTimeout() {
    const int ms = NetworkConfiguration::UdpAssociateIdleTimeoutMs > 0
                       ? NetworkConfiguration::UdpAssociateIdleTimeoutMs
                       : 120'000;
    return std::chrono::milliseconds(ms);
}

UdpRelay::UdpRelay(IocpService& iocp,
                   DnsResolver& dns,
                   const sockaddr_storage& clientTcpEndPoint,
                   const sockaddr_storage& clientTcpLocalEndPoint,
                   FriendlyNameResolver& resolver,
                   StopCallback onStopped)
    : iocp_(iocp),
      dns_(dns),
      resolver_(resolver),
      onStopped_(std::move(onStopped)),
      clientTcpEndPoint_(clientTcpEndPoint),
      clientTcpLocalEndPoint_(clientTcpLocalEndPoint),
      recvCtx_(IoOp::RecvFrom, 65536),
      lastActivity_(std::chrono::steady_clock::now()),
      lastCleanup_(std::chrono::steady_clock::now()) {}

UdpRelay::~UdpRelay() {
    Stop(false);
    WaitPendingZero(-1);
}

bool UdpRelay::BindRelaySocket() {
    // Bind to the TCP local address the client connected to (reachable BND.ADDR),
    // falling back to output bind / ANY.
    auto tryBind = [&](const sockaddr_storage& addrTemplate) -> bool {
        sockaddr_storage bindAddr = addrTemplate;
        if (bindAddr.ss_family == AF_INET) {
            reinterpret_cast<sockaddr_in*>(&bindAddr)->sin_port = 0;
        } else if (bindAddr.ss_family == AF_INET6) {
            reinterpret_cast<sockaddr_in6*>(&bindAddr)->sin6_port = 0;
        } else {
            return false;
        }

        if (udpSocket_ != INVALID_SOCKET) {
            closesocket(udpSocket_);
            udpSocket_ = INVALID_SOCKET;
        }
        udpSocket_ = IocpService::CreateUdpSocket(bindAddr.ss_family);
        if (udpSocket_ == INVALID_SOCKET) return false;

        setsockopt(udpSocket_, SOL_SOCKET, SO_SNDBUF,
                   reinterpret_cast<const char*>(&NetworkConfiguration::SendBufferSize), sizeof(int));
        setsockopt(udpSocket_, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<const char*>(&NetworkConfiguration::ReceiveBufferSize), sizeof(int));

        const int bindLen = bindAddr.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        if (bind(udpSocket_, reinterpret_cast<sockaddr*>(&bindAddr), bindLen) != 0) {
            closesocket(udpSocket_);
            udpSocket_ = INVALID_SOCKET;
            return false;
        }
        return true;
    };

    if (tryBind(clientTcpLocalEndPoint_)) {
        return true;
    }

    sockaddr_storage output{};
    int outLen = 0;
    if (NetworkConfiguration::FillOutputBindAddress(output, outLen) && tryBind(output)) {
        return true;
    }

    sockaddr_storage anyAddr{};
    if (clientTcpEndPoint_.ss_family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&anyAddr);
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = INADDR_ANY;
        v4->sin_port = 0;
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&anyAddr);
        v6->sin6_family = AF_INET6;
        v6->sin6_port = 0;
    }
    return tryBind(anyAddr);
}

bool UdpRelay::Start() {
    if (!BindRelaySocket()) {
        return false;
    }

    int localLen = sizeof(localEndPoint_);
    getsockname(udpSocket_, reinterpret_cast<sockaddr*>(&localEndPoint_), &localLen);
    advertisedEndPoint_ = localEndPoint_;

    // Replace wildcard bind address with the client-facing TCP local IP.
    if (NetworkUtils::IsAnyAddress(NetworkUtils::IPToString(
            reinterpret_cast<sockaddr*>(&advertisedEndPoint_)))) {
        const uint16_t port = localEndPoint_.ss_family == AF_INET
                                  ? ntohs(reinterpret_cast<sockaddr_in*>(&localEndPoint_)->sin_port)
                                  : ntohs(reinterpret_cast<sockaddr_in6*>(&localEndPoint_)->sin6_port);
        advertisedEndPoint_ = clientTcpLocalEndPoint_;
        if (advertisedEndPoint_.ss_family == AF_INET) {
            reinterpret_cast<sockaddr_in*>(&advertisedEndPoint_)->sin_port = htons(port);
        } else if (advertisedEndPoint_.ss_family == AF_INET6) {
            reinterpret_cast<sockaddr_in6*>(&advertisedEndPoint_)->sin6_port = htons(port);
        }
    }

    if (!iocp_.Associate(udpSocket_, shared_from_this())) {
        closesocket(udpSocket_);
        udpSocket_ = INVALID_SOCKET;
        return false;
    }

    Logger::Instance().Info(
        "UDP relay started on {Local}{FriendlyLocal} for client {Client}{FriendlyClient}.",
        NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&advertisedEndPoint_)),
        resolver_.FriendlySuffix(reinterpret_cast<sockaddr*>(&advertisedEndPoint_)),
        NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&clientTcpEndPoint_)),
        resolver_.FriendlySuffix(reinterpret_cast<sockaddr*>(&clientTcpEndPoint_)));

    return PostNextRecv();
}

void UdpRelay::Stop(bool notifySession) {
    std::lock_guard completionLock(completionMutex_);
    if (stop_.exchange(true)) {
        return;
    }
    if (udpSocket_ != INVALID_SOCKET) {
        closesocket(udpSocket_);
        udpSocket_ = INVALID_SOCKET;
    }
    {
        std::lock_guard lock(stateMutex_);
        pendingSends_.clear();
        fragAssemblies_.clear();
        pendingByDomain_.clear();
        dnsInFlight_.clear();
    }
    if (notifySession && onStopped_) {
        auto cb = std::move(onStopped_);
        onStopped_ = nullptr;
        cb();
    }
}

bool UdpRelay::PostNextRecv() {
    if (stop_ || udpSocket_ == INVALID_SOCKET) return false;
    return iocp_.PostRecvFrom(udpSocket_, &recvCtx_, shared_from_this());
}

void UdpRelay::OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) {
    if (!ctx) return;

    if (ctx->op == IoOp::User) {
        std::unique_ptr<DnsNotify> notify;
        {
            std::lock_guard lock(stateMutex_);
            auto it = dnsNotifies_.find(ctx);
            if (it == dnsNotifies_.end()) return;
            notify = std::move(it->second);
            dnsNotifies_.erase(it);
        }
        if (!stop_ && notify) {
            OnDnsNotify(*notify);
        }
        return;
    }

    if (ctx->op == IoOp::SendTo) {
        OnSendCompleted(ctx);
        return;
    }

    if (stop_) return;

    if (ctx == &recvCtx_) {
        if (error == 0 && bytes > 0) {
            lastActivity_ = std::chrono::steady_clock::now();
            try {
                HandlePacket(reinterpret_cast<const uint8_t*>(recvCtx_.buffer.data()),
                             static_cast<int>(bytes), recvCtx_.addr);
                if (std::chrono::steady_clock::now() - lastCleanup_ > kCleanupInterval) {
                    CleanupState();
                    lastCleanup_ = std::chrono::steady_clock::now();
                }
            } catch (const std::exception& ex) {
                Logger::Instance().Warning("UDP processing error: {Error}", ex.what());
            }
        }

        if (std::chrono::steady_clock::now() - lastActivity_ > UdpIdleTimeout()) {
            Logger::Instance().Info("UDP relay idle timeout reached");
            Stop();
            return;
        }

        PostNextRecv();
        return;
    }
}

void UdpRelay::OnSendCompleted(IoContext* ctx) {
    std::lock_guard lock(stateMutex_);
    for (auto it = inFlightSends_.begin(); it != inFlightSends_.end(); ++it) {
        if (&(*it)->ctx == ctx) {
            inFlightSends_.erase(it);
            break;
        }
    }
    if (sendsInFlight_ > 0) {
        --sendsInFlight_;
    }
    if (!stop_) {
        PumpSendLocked();
    }
}

void UdpRelay::HandlePacket(const uint8_t* data, int length, const sockaddr_storage& remote) {
    if (!actualClientUdpEndPoint_) {
        const std::string remoteIp = NetworkUtils::IPToString(reinterpret_cast<const sockaddr*>(&remote));
        const std::string clientIp = NetworkUtils::IPToString(reinterpret_cast<const sockaddr*>(&clientTcpEndPoint_));
        if (remoteIp == clientIp) {
            actualClientUdpEndPoint_ = remote;
            Logger::Instance().Debug(
                "Tracked UDP endpoint {Endpoint}{Friendly}",
                NetworkUtils::EndpointToString(reinterpret_cast<const sockaddr*>(&remote)),
                resolver_.FriendlySuffix(reinterpret_cast<const sockaddr*>(&remote)));
        } else {
            return;
        }
    }

    const EndpointKey remoteKey = EndpointKey::From(remote);
    const EndpointKey clientKey = EndpointKey::From(*actualClientUdpEndPoint_);
    if (remoteKey == clientKey) {
        HandleClientPacket(data, length);
    } else {
        HandleServerResponse(data, length, remote);
    }
}

void UdpRelay::EnqueueSend(std::vector<char> data, const sockaddr_storage& to) {
    std::lock_guard lock(stateMutex_);
    EnqueueSendLocked(std::move(data), to);
}

void UdpRelay::EnqueueSendLocked(std::vector<char> data, const sockaddr_storage& to) {
    if (pendingSends_.size() >= kMaxPendingUdpSends) {
        Logger::Instance().Warning("UDP send queue limit reached; dropping datagram.");
        return;
    }
    auto out = std::make_unique<Outbound>();
    out->data = std::move(data);
    out->to = to;
    out->toLen = to.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    pendingSends_.push_back(std::move(out));
    PumpSendLocked();
}

void UdpRelay::PumpSendLocked() {
    while (sendsInFlight_ < kMaxUdpSendsInFlight && !pendingSends_.empty() &&
           !stop_ && udpSocket_ != INVALID_SOCKET) {
        auto out = std::move(pendingSends_.front());
        pendingSends_.pop_front();
        Outbound* raw = out.get();
        if (!iocp_.PostSendTo(udpSocket_, &raw->ctx, raw->data.data(), raw->data.size(),
                              reinterpret_cast<sockaddr*>(&raw->to), raw->toLen, shared_from_this())) {
            pendingSends_.push_front(std::move(out));
            Logger::Instance().Warning("Failed to post UDP send; waiting for retry.");
            break;
        }
        inFlightSends_.push_back(std::move(out));
        ++sendsInFlight_;
    }
}

void UdpRelay::ForwardPayload(const uint8_t* payload, int payloadLen, const sockaddr_storage& destination) {
    if (payloadLen < 0) return;
    std::vector<char> data(reinterpret_cast<const char*>(payload),
                           reinterpret_cast<const char*>(payload) + payloadLen);
    {
        std::lock_guard lock(stateMutex_);
        const EndpointKey key = EndpointKey::From(destination);
        if (!activeDestinations_.count(key) &&
            activeDestinations_.size() >= kMaxActiveDestinations) {
            activeDestinations_.erase(activeDestinations_.begin());
        }
        activeDestinations_[key] = std::chrono::steady_clock::now();
        EnqueueSendLocked(std::move(data), destination);
    }
}

void UdpRelay::DispatchClientPayload(const sockaddr_storage* ipDestination,
                                     const std::string* domain,
                                     uint16_t port,
                                     const uint8_t* payload,
                                     int payloadLen) {
    if (payloadLen < 0) return;

    if (ipDestination) {
        ForwardPayload(payload, payloadLen, *ipDestination);
        return;
    }

    if (!domain || domain->empty()) return;

    PendingDomainPacket pending;
    pending.port = port;
    pending.payload.assign(payload, payload + payloadLen);

    bool startResolve = false;
    {
        std::lock_guard lock(stateMutex_);
        auto& queue = pendingByDomain_[*domain];
        if ((queue.empty() && pendingByDomain_.size() > kMaxPendingDomains) ||
            queue.size() >= kMaxPacketsPerDomain) {
            if (queue.empty()) {
                pendingByDomain_.erase(*domain);
            }
            Logger::Instance().Warning("UDP DNS pending queue limit reached; dropping datagram.");
            return;
        }
        queue.push_back(std::move(pending));
        if (dnsInFlight_.insert(*domain).second) {
            startResolve = true;
        }
    }
    if (!startResolve) return;

    auto self = std::static_pointer_cast<UdpRelay>(shared_from_this());
    const std::string domainCopy = *domain;
    dns_.ResolveAsync(domainCopy, [self, domainCopy](std::optional<std::string> ip) {
        if (self->stop_) return;
        auto notify = std::make_unique<DnsNotify>();
        notify->domain = domainCopy;
        notify->ip = std::move(ip);
        IoContext* ctx = &notify->ctx;
        {
            std::lock_guard lock(self->stateMutex_);
            self->dnsNotifies_[ctx] = std::move(notify);
        }
        if (!self->iocp_.PostUser(self, ctx)) {
            std::lock_guard lock(self->stateMutex_);
            self->dnsNotifies_.erase(ctx);
            self->dnsInFlight_.erase(domainCopy);
            self->pendingByDomain_.erase(domainCopy);
        }
    });
}

bool UdpRelay::ProcessFragment(uint8_t frag,
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
                               uint16_t& outPort) {
    const uint8_t fragNum = static_cast<uint8_t>(frag & socks5::UdpFrag::NumberMask);
    const bool isLast = (frag & socks5::UdpFrag::LastFlag) != 0;
    if (fragNum == 0) {
        Logger::Instance().Debug("Invalid UDP FRAG (zero number) dropped");
        return false;
    }
    if (payloadLen < 0) return false;

    std::lock_guard lock(stateMutex_);
    const auto now = std::chrono::steady_clock::now();

    if (fragNum == 1) {
        if (!fragAssemblies_.count(assemblyKey) &&
            fragAssemblies_.size() >= kMaxFragmentAssemblies) {
            Logger::Instance().Warning("UDP fragment assembly limit reached; dropping fragment.");
            return false;
        }
        FragAssembly assembly;
        assembly.updated = now;
        assembly.port = port;
        if (ipDestination) {
            assembly.destination = *ipDestination;
            assembly.hasIpDestination = true;
        } else if (domain) {
            assembly.domain = *domain;
        }
        fragAssemblies_[assemblyKey] = std::move(assembly);
    } else if (!fragAssemblies_.count(assemblyKey)) {
        Logger::Instance().Debug("Orphan UDP fragment {Frag} dropped", static_cast<int>(fragNum));
        return false;
    }

    FragAssembly& assembly = fragAssemblies_[assemblyKey];
    assembly.updated = now;
    const auto existing = assembly.parts.find(fragNum);
    const size_t oldSize = existing == assembly.parts.end() ? 0 : existing->second.size();
    const size_t newSize = static_cast<size_t>(payloadLen);
    if (newSize > kMaxAssembledUdpPayload ||
        assembly.totalBytes - oldSize > kMaxAssembledUdpPayload - newSize) {
        fragAssemblies_.erase(assemblyKey);
        return false;
    }
    assembly.parts[fragNum].assign(payload, payload + payloadLen);
    assembly.totalBytes = assembly.totalBytes - oldSize + newSize;
    if (isLast) {
        assembly.haveLast = true;
        assembly.lastFragNum = fragNum;
    }

    if (!assembly.haveLast) {
        return false;
    }

    size_t total = 0;
    for (uint8_t i = 1; i <= assembly.lastFragNum; ++i) {
        auto it = assembly.parts.find(i);
        if (it == assembly.parts.end()) {
            return false;
        }
        total += it->second.size();
        if (total > kMaxAssembledUdpPayload) {
            Logger::Instance().Warning("UDP FRAG assembly exceeds max size, discarded");
            fragAssemblies_.erase(assemblyKey);
            return false;
        }
    }

    outPayload.clear();
    outPayload.reserve(total);
    for (uint8_t i = 1; i <= assembly.lastFragNum; ++i) {
        const auto& part = assembly.parts[i];
        outPayload.insert(outPayload.end(), part.begin(), part.end());
    }

    outHasIp = assembly.hasIpDestination;
    outIpDestination = assembly.destination;
    outDomain = std::move(assembly.domain);
    outPort = assembly.port;
    const int fragCount = static_cast<int>(assembly.lastFragNum);
    const int byteCount = static_cast<int>(outPayload.size());
    fragAssemblies_.erase(assemblyKey);

    Logger::Instance().Debug(
        "UDP FRAG reassembled {Count} fragments, {Bytes} bytes",
        fragCount,
        byteCount);
    return true;
}

void UdpRelay::HandleClientPacket(const uint8_t* data, int length) {
    if (!actualClientUdpEndPoint_ || length < 4) return;

    int offset = 2;
    const uint8_t frag = data[offset++];
    const uint8_t atyp = data[offset++];

    sockaddr_storage destination{};
    std::memset(&destination, 0, sizeof(destination));
    std::string domain;
    uint16_t port = 0;
    bool hasIpDestination = false;
    std::string assemblyKey;

    if (atyp == socks5::AddressType::IPv4) {
        if (length < offset + 6) return;
        auto* v4 = reinterpret_cast<sockaddr_in*>(&destination);
        v4->sin_family = AF_INET;
        std::memcpy(&v4->sin_addr, data + offset, 4);
        port = static_cast<uint16_t>((data[offset + 4] << 8) | data[offset + 5]);
        v4->sin_port = htons(port);
        offset += 6;
        hasIpDestination = true;
        assemblyKey = NetworkUtils::EndpointToString(reinterpret_cast<const sockaddr*>(&destination));
    } else if (atyp == socks5::AddressType::IPv6) {
        if (length < offset + 18) return;
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&destination);
        v6->sin6_family = AF_INET6;
        std::memcpy(&v6->sin6_addr, data + offset, 16);
        port = static_cast<uint16_t>((data[offset + 16] << 8) | data[offset + 17]);
        v6->sin6_port = htons(port);
        offset += 18;
        hasIpDestination = true;
        assemblyKey = NetworkUtils::EndpointToString(reinterpret_cast<const sockaddr*>(&destination));
    } else if (atyp == socks5::AddressType::DomainName) {
        if (length < offset + 1) return;
        const uint8_t len = data[offset++];
        if (len == 0 || length < offset + len + 2) return;
        domain.assign(reinterpret_cast<const char*>(data + offset), len);
        offset += len;
        port = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        offset += 2;
        assemblyKey = "d:" + domain + ":" + std::to_string(port);
    } else {
        return;
    }

    const uint8_t* payload = data + offset;
    const int payloadLen = length - offset;
    if (payloadLen < 0) return;

    if (frag == socks5::UdpFrag::Standalone) {
        DispatchClientPayload(hasIpDestination ? &destination : nullptr,
                              hasIpDestination ? nullptr : &domain,
                              port,
                              payload,
                              payloadLen);
        return;
    }

    std::vector<uint8_t> assembled;
    sockaddr_storage outDest{};
    bool outHasIp = false;
    std::string outDomain;
    uint16_t outPort = 0;
    if (!ProcessFragment(frag,
                         assemblyKey,
                         hasIpDestination ? &destination : nullptr,
                         hasIpDestination ? nullptr : &domain,
                         port,
                         payload,
                         payloadLen,
                         assembled,
                         outDest,
                         outHasIp,
                         outDomain,
                         outPort)) {
        return;
    }

    DispatchClientPayload(outHasIp ? &outDest : nullptr,
                          outHasIp ? nullptr : &outDomain,
                          outPort,
                          assembled.data(),
                          static_cast<int>(assembled.size()));
}

void UdpRelay::OnDnsNotify(DnsNotify& notify) {
    if (stop_) return;

    const std::optional<std::string> resolvedIp = notify.ip;
    while (true) {
        std::deque<PendingDomainPacket> batch;
        {
            std::lock_guard lock(stateMutex_);
            auto it = pendingByDomain_.find(notify.domain);
            if (it == pendingByDomain_.end() || it->second.empty()) {
                dnsInFlight_.erase(notify.domain);
                return;
            }
            batch = std::move(it->second);
            it->second.clear();
        }

        if (!resolvedIp) {
            size_t dropped = batch.size();
            {
                std::lock_guard lock(stateMutex_);
                auto it = pendingByDomain_.find(notify.domain);
                if (it != pendingByDomain_.end()) {
                    dropped += it->second.size();
                    pendingByDomain_.erase(it);
                }
                dnsInFlight_.erase(notify.domain);
            }
            Logger::Instance().Warning("UDP DNS lookup failed for {Domain}, dropping {Count} packet(s).",
                                       notify.domain, dropped);
            return;
        }

        sockaddr_storage destination{};
        int family = 0;
        if (!NetworkUtils::ParseIP(*resolvedIp, destination, family)) {
            Logger::Instance().Warning("UDP DNS returned invalid IP for {Domain}.", notify.domain);
            continue;
        }

        for (const PendingDomainPacket& pending : batch) {
            if (family == AF_INET) {
                reinterpret_cast<sockaddr_in*>(&destination)->sin_port = htons(pending.port);
            } else {
                reinterpret_cast<sockaddr_in6*>(&destination)->sin6_port = htons(pending.port);
            }
            ForwardPayload(pending.payload.data(), static_cast<int>(pending.payload.size()), destination);
        }
    }
}

void UdpRelay::HandleServerResponse(const uint8_t* data, int length, const sockaddr_storage& source) {
    if (!actualClientUdpEndPoint_) return;

    {
        std::lock_guard lock(stateMutex_);
        if (!activeDestinations_.count(EndpointKey::From(source))) {
            return;
        }
    }

    const int headerLen = source.ss_family == AF_INET ? 10 : 22;
    std::vector<char> packet(static_cast<size_t>(headerLen + length));
    int offset = 0;
    packet[offset++] = 0;
    packet[offset++] = 0;
    packet[offset++] = 0;

    if (source.ss_family == AF_INET) {
        packet[offset++] = static_cast<char>(socks5::AddressType::IPv4);
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&source);
        std::memcpy(packet.data() + offset, &v4->sin_addr, 4);
        offset += 4;
        const uint16_t port = ntohs(v4->sin_port);
        packet[offset++] = static_cast<char>(port >> 8);
        packet[offset++] = static_cast<char>(port & 0xFF);
    } else {
        packet[offset++] = static_cast<char>(socks5::AddressType::IPv6);
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&source);
        std::memcpy(packet.data() + offset, &v6->sin6_addr, 16);
        offset += 16;
        const uint16_t port = ntohs(v6->sin6_port);
        packet[offset++] = static_cast<char>(port >> 8);
        packet[offset++] = static_cast<char>(port & 0xFF);
    }

    std::memcpy(packet.data() + offset, data, static_cast<size_t>(length));
    EnqueueSend(std::move(packet), *actualClientUdpEndPoint_);
}

void UdpRelay::CleanupState() {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(stateMutex_);
    for (auto it = activeDestinations_.begin(); it != activeDestinations_.end();) {
        if (now - it->second > UdpIdleTimeout()) it = activeDestinations_.erase(it);
        else ++it;
    }
    for (auto it = fragAssemblies_.begin(); it != fragAssemblies_.end();) {
        if (now - it->second.updated > kFragReassemblyTimeout) {
            Logger::Instance().Debug("UDP FRAG reassembly timed out for {Key}", it->first);
            it = fragAssemblies_.erase(it);
        } else {
            ++it;
        }
    }
}
