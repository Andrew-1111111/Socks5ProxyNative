#include "Socks5Session.h"

#include "../ProxyServer.h"
#include "Socks5Constants.h"
#include "../../config/NetworkConfiguration.h"
#include "../../utils/Logger.h"

#include <mstcpip.h>

#include <algorithm>
#include <cstring>
#include <string_view>

namespace {
constexpr size_t kProtoBuf = 4096;
constexpr size_t kMaxRelayQueueDepth = 32;
constexpr size_t kMaxProtocolBuffered = 1024 * 1024;
constexpr size_t kGssRelayChunk = 16 * 1024;

std::string DescribeNonSocks5FirstByte(uint8_t b) {
    switch (b) {
    case 'C':
        return "Looks like HTTP CONNECT: the client may be configured for HTTP/HTTPS proxy instead of SOCKS5.";
    case 'G':
        return "Looks like HTTP GET: the client may be configured for HTTP proxy instead of SOCKS5.";
    case 'H':
        return "Looks like HTTP HEAD: the client may be configured for HTTP proxy instead of SOCKS5.";
    case 'P':
        return "Looks like HTTP POST: the client may be configured for HTTP proxy instead of SOCKS5.";
    case 0x16:
        return "Looks like TLS ClientHello: the client sent HTTPS traffic directly to the SOCKS5 port.";
    default:
        if (b >= 32 && b < 127) {
            return std::string("Expected SOCKS5 handshake (first byte 0x05), got ASCII '") +
                   static_cast<char>(b) + "' — not a SOCKS5 client.";
        }
        return "Expected SOCKS5 handshake (first byte 0x05), not this protocol.";
    }
}

bool ConstantTimeEqual(std::string_view lhs, std::string_view rhs) {
    const size_t maxLength = (std::max)(lhs.size(), rhs.size());
    unsigned difference = static_cast<unsigned>(lhs.size() ^ rhs.size());
    for (size_t i = 0; i < maxLength; ++i) {
        const unsigned a = i < lhs.size() ? static_cast<unsigned char>(lhs[i]) : 0;
        const unsigned b = i < rhs.size() ? static_cast<unsigned char>(rhs[i]) : 0;
        difference |= a ^ b;
    }
    return difference == 0;
}
}

Socks5Session::Socks5Session(IocpService& iocp,
                             ProxyServer& server,
                             SOCKET client,
                             DnsResolver& dns,
                             FriendlyNameResolver& resolver,
                             bool slotHeld)
    : iocp_(iocp),
      server_(server),
      dns_(dns),
      resolver_(resolver),
      client_(client),
      clientIo_(static_cast<size_t>(NetworkConfiguration::BufferSize)),
      destIo_(static_cast<size_t>(NetworkConfiguration::BufferSize)),
      slotHeld_(slotHeld) {
    int len = sizeof(clientEp_);
    getpeername(client_, reinterpret_cast<sockaddr*>(&clientEp_), &len);
    len = sizeof(clientLocalEp_);
    getsockname(client_, reinterpret_cast<sockaddr*>(&clientLocalEp_), &len);
    ConfigureSocket(client_);
}

Socks5Session::~Socks5Session() {
    closed_ = true;
    CancelConnectTimer();
    CancelIdleTimer();
    if (udpRelay_) {
        udpRelay_->Stop(false);
        udpRelay_.reset();
    }
    if (client_ != INVALID_SOCKET) {
        closesocket(client_);
        client_ = INVALID_SOCKET;
    }
    if (dest_ != INVALID_SOCKET) {
        closesocket(dest_);
        dest_ = INVALID_SOCKET;
    }
}

void Socks5Session::ConfigureSocket(SOCKET s) {
    setsockopt(s, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&NetworkConfiguration::SendBufferSize), sizeof(int));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&NetworkConfiguration::ReceiveBufferSize), sizeof(int));

    if (NetworkConfiguration::SendTimeoutMs > 0) {
        DWORD ms = static_cast<DWORD>(NetworkConfiguration::SendTimeoutMs);
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
    }
    if (NetworkConfiguration::ReceiveTimeoutMs > 0) {
        DWORD ms = static_cast<DWORD>(NetworkConfiguration::ReceiveTimeoutMs);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
    }

    BOOL nodelay = NetworkConfiguration::NoDelay ? TRUE : FALSE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    linger ling{};
    ling.l_onoff = NetworkConfiguration::LingerEnabled ? 1 : 0;
    ling.l_linger = static_cast<u_short>(
        NetworkConfiguration::LingerTimeoutSec > 0 ? NetworkConfiguration::LingerTimeoutSec : 0);
    setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&ling), sizeof(ling));

    BOOL keepAlive = NetworkConfiguration::KeepAlive ? TRUE : FALSE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&keepAlive), sizeof(keepAlive));
    if (NetworkConfiguration::KeepAlive) {
        tcp_keepalive ka{};
        ka.onoff = 1;
        ka.keepalivetime = static_cast<ULONG>(
            (NetworkConfiguration::TcpKeepAliveTime > 0 ? NetworkConfiguration::TcpKeepAliveTime : 60) * 1000UL);
        ka.keepaliveinterval = static_cast<ULONG>(
            (NetworkConfiguration::TcpKeepAliveInterval > 0 ? NetworkConfiguration::TcpKeepAliveInterval : 10) * 1000UL);
        DWORD bytes = 0;
        WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes, nullptr, nullptr);

        // Windows 10+: TCP_KEEPCNT (17) — probe count before giving up.
        if (NetworkConfiguration::TcpKeepAliveRetryCount > 0) {
            DWORD probes = static_cast<DWORD>(NetworkConfiguration::TcpKeepAliveRetryCount);
            setsockopt(s, IPPROTO_TCP, 17 /*TCP_KEEPCNT*/, reinterpret_cast<const char*>(&probes), sizeof(probes));
        }
    }
}

bool Socks5Session::Start() {
    if (!iocp_.Associate(client_, shared_from_this())) {
        return false;
    }

    const std::string ep = NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&clientEp_));
    const std::string friendly = resolver_.FriendlySuffix(reinterpret_cast<sockaddr*>(&clientEp_));
    Logger::Instance().Info("New client connection from {ClientEndPoint}{Friendly}.", ep, friendly);

    state_ = SessionState::Handshake;
    ArmIdleTimer();
    return BeginClientRead();
}

void Socks5Session::Close() {
    std::lock_guard completionLock(completionMutex_);
    if (closed_.exchange(true)) {
        return;
    }

    auto self = shared_from_this();
    CancelConnectTimer();
    CancelIdleTimer();
    closeAfterFlush_ = false;

    const std::string ep = NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&clientEp_));
    const std::string friendly = resolver_.FriendlySuffix(reinterpret_cast<sockaddr*>(&clientEp_));
    Logger::Instance().Info("Connection closed for client {ClientEndPoint}{Friendly}.", ep, friendly);

    if (udpRelay_) {
        std::shared_ptr<UdpRelay> relay = std::move(udpRelay_);
        relay->Stop(false);
        relay->WaitPendingZero(-1);
    }

    if (client_ != INVALID_SOCKET) {
        shutdown(client_, SD_BOTH);
        closesocket(client_);
        client_ = INVALID_SOCKET;
    }
    if (dest_ != INVALID_SOCKET) {
        shutdown(dest_, SD_BOTH);
        closesocket(dest_);
        dest_ = INVALID_SOCKET;
    }

    server_.OnSessionClosed(std::static_pointer_cast<Socks5Session>(self), slotHeld_);
}

void Socks5Session::ArmIdleTimer() {
    CancelIdleTimer();
    if (NetworkConfiguration::IdleTimeoutMs <= 0) return;
    if (state_ == SessionState::Relaying || state_ == SessionState::UdpAssociate ||
        state_ == SessionState::Resolving || state_ == SessionState::Connecting) {
        return;
    }
    const uint64_t generation = ++idleTimerGeneration_;
    idleTimerId_ = iocp_.ScheduleTimeout(
        shared_from_this(), (generation << 8) | kTimerIdle,
        NetworkConfiguration::IdleTimeoutMs);
}

void Socks5Session::CancelIdleTimer() {
    ++idleTimerGeneration_;
    if (idleTimerId_ != 0) {
        iocp_.CancelTimeout(idleTimerId_);
        idleTimerId_ = 0;
    }
}

bool Socks5Session::ArmConnectTimer() {
    CancelConnectTimer();
    if (NetworkConfiguration::ConnectTimeoutMs <= 0) return true;
    const uint64_t generation = ++connectTimerGeneration_;
    connectTimerId_ = iocp_.ScheduleTimeout(
        shared_from_this(), (generation << 8) | kTimerConnect,
        NetworkConfiguration::ConnectTimeoutMs);
    return connectTimerId_ != 0;
}

void Socks5Session::CancelConnectTimer() {
    ++connectTimerGeneration_;
    if (connectTimerId_ != 0) {
        iocp_.CancelTimeout(connectTimerId_);
        connectTimerId_ = 0;
    }
}

void Socks5Session::RequestCloseAfterFlush() {
    closeAfterFlush_ = true;
    bool empty = false;
    {
        std::lock_guard lock(mutex_);
        empty = clientIo_.sendQueue.empty() && !clientIo_.sending;
    }
    if (empty) {
        Close();
    }
}

void Socks5Session::FailAndClose(uint8_t replyCode) {
    if (closed_ || state_ == SessionState::Closing) {
        return;
    }
    state_ = SessionState::Closing;
    CancelConnectTimer();
    CancelIdleTimer();
    if (dest_ != INVALID_SOCKET) {
        closesocket(dest_);
        dest_ = INVALID_SOCKET;
    }
    SendSocksReply(replyCode);
    RequestCloseAfterFlush();
}

void Socks5Session::OnUdpRelayStopped() {
    if (closed_) return;
    Logger::Instance().Info("UDP ASSOCIATE ended (relay stopped), closing TCP control connection.");
    Close();
}

bool Socks5Session::BeginClientRead() {
    if (closed_ || clientIo_.reading) return false;
    clientIo_.reading = true;
    if (!iocp_.PostRecv(client_, &clientIo_.recvCtx, shared_from_this())) {
        clientIo_.reading = false;
        Close();
        return false;
    }
    return true;
}

void Socks5Session::OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) {
    if (!ctx) {
        Close();
        return;
    }

    if (closed_) {
        if (ctx == &clientIo_.recvCtx) clientIo_.reading = false;
        if (ctx == &clientIo_.sendCtx) clientIo_.sending = false;
        if (ctx == &destIo_.recvCtx) destIo_.reading = false;
        if (ctx == &destIo_.sendCtx) destIo_.sending = false;
        return;
    }

    if (ctx->op == IoOp::User) {
        // DNS completion uses dnsCtx_ without userKey; timers set userKey.
        if (ctx == &dnsCtx_) {
            OnDnsResolved();
            return;
        }
        if (ctx == &udpStopCtx_) {
            OnUdpRelayStopped();
            return;
        }
        OnTimer(ctx->userKey);
        return;
    }

    if (ctx == &connectCtx_) {
        OnDestConnect(error);
        return;
    }
    if (ctx == &clientIo_.recvCtx) {
        clientIo_.reading = false;
        OnClientRecv(bytes, error);
        return;
    }
    if (ctx == &clientIo_.sendCtx) {
        OnClientSend(bytes, error);
        return;
    }
    if (ctx == &destIo_.recvCtx) {
        destIo_.reading = false;
        OnDestRecv(bytes, error);
        return;
    }
    if (ctx == &destIo_.sendCtx) {
        OnDestSend(bytes, error);
        return;
    }
}

void Socks5Session::OnTimer(uint64_t kind) {
    if (closed_) return;
    const uint64_t timerKind = kind & 0xFF;
    const uint64_t generation = kind >> 8;
    if (timerKind == kTimerConnect) {
        if (generation != connectTimerGeneration_) return;
        connectTimerId_ = 0;
        if (state_ != SessionState::Connecting) return;
        Logger::Instance().Warning("Connect timed out.");
        if (dest_ != INVALID_SOCKET) {
            closesocket(dest_);
            dest_ = INVALID_SOCKET;
        }
        FailAndClose(socks5::ReplyCode::TtlExpired);
        return;
    }
    if (timerKind == kTimerIdle) {
        if (generation != idleTimerGeneration_) return;
        idleTimerId_ = 0;
        if (state_ == SessionState::Relaying || state_ == SessionState::UdpAssociate ||
            state_ == SessionState::Resolving || state_ == SessionState::Connecting ||
            state_ == SessionState::Closing) {
            return;
        }
        Logger::Instance().Warning("Session idle timeout during handshake/request.");
        Close();
    }
}

void Socks5Session::OnClientRecv(DWORD bytes, DWORD error) {
    if (error != 0 || bytes == 0) {
        if (state_ == SessionState::Relaying) {
            clientIo_.peerClosed = true;
            if (dest_ != INVALID_SOCKET) {
                shutdown(dest_, SD_SEND);
            }
            if (destIo_.peerClosed) Close();
            return;
        }
        Close();
        return;
    }

    if (state_ == SessionState::Handshake || state_ == SessionState::Auth ||
        state_ == SessionState::GssapiAuth || state_ == SessionState::GssapiProtect ||
        state_ == SessionState::Request) {
        ArmIdleTimer();
    }

    if (state_ == SessionState::UdpAssociate) {
        BeginClientRead();
        return;
    }

    if (state_ == SessionState::Relaying) {
        OnRelayData(StreamTag::Client, bytes);
        return;
    }

    if (bytes > kMaxProtocolBuffered ||
        ingest_.size() > kMaxProtocolBuffered - static_cast<size_t>(bytes)) {
        Logger::Instance().Warning("SOCKS protocol input exceeded the buffering limit.");
        Close();
        return;
    }
    ingest_.insert(ingest_.end(),
                   clientIo_.recvCtx.buffer.begin(),
                   clientIo_.recvCtx.buffer.begin() + static_cast<std::ptrdiff_t>(bytes));

    while (!closed_ &&
           (state_ == SessionState::Handshake || state_ == SessionState::Auth ||
            state_ == SessionState::GssapiAuth || state_ == SessionState::GssapiProtect ||
            state_ == SessionState::Request)) {
        const SessionState before = state_;
        const size_t sizeBefore = ingest_.size();
        bool ok = true;
        switch (state_) {
        case SessionState::Handshake: ok = ProcessHandshakeBuffer(); break;
        case SessionState::Auth: ok = ProcessAuthBuffer(); break;
        case SessionState::GssapiAuth: ok = ProcessGssapiAuthBuffer(); break;
        case SessionState::GssapiProtect: ok = ProcessGssapiProtectBuffer(); break;
        case SessionState::Request: ok = ProcessRequestBuffer(); break;
        default: break;
        }
        if (!ok) {
            RequestCloseAfterFlush();
            return;
        }
        // Do not recv during Resolving/Connecting: bytes can land in ingest_ and
        // be discarded by StartRelay()'s ingest_.clear().
        if (state_ != SessionState::Handshake && state_ != SessionState::Auth &&
            state_ != SessionState::GssapiAuth && state_ != SessionState::GssapiProtect &&
            state_ != SessionState::Request) {
            return;
        }
        if (state_ == before && ingest_.size() == sizeBefore) {
            break;
        }
    }

    if (state_ == SessionState::Handshake || state_ == SessionState::Auth ||
        state_ == SessionState::GssapiAuth || state_ == SessionState::GssapiProtect ||
        state_ == SessionState::Request) {
        BeginClientRead();
    }
}

void Socks5Session::OnClientSend(DWORD bytes, DWORD error) {
    clientIo_.sending = false;
    if (error != 0) {
        Close();
        return;
    }

    {
        std::lock_guard lock(mutex_);
        if (!clientIo_.sendQueue.empty()) {
            clientIo_.sendFrontOffset += static_cast<size_t>(bytes);
            auto& front = clientIo_.sendQueue.front();
            if (clientIo_.sendFrontOffset >= front.size()) {
                clientIo_.sendQueue.pop_front();
                clientIo_.sendFrontOffset = 0;
            }
        }
    }
    PumpSend(StreamTag::Client);

    if (closeAfterFlush_) {
        bool empty = false;
        {
            std::lock_guard lock(mutex_);
            empty = clientIo_.sendQueue.empty() && !clientIo_.sending;
        }
        if (empty) {
            Close();
            return;
        }
    }

    MaybeResumeRelayRead(StreamTag::Dest);
}

void Socks5Session::OnDestRecv(DWORD bytes, DWORD error) {
    if (error != 0 || bytes == 0) {
        destIo_.peerClosed = true;
        if (client_ != INVALID_SOCKET) {
            shutdown(client_, SD_SEND);
        }
        if (clientIo_.peerClosed) Close();
        return;
    }
    OnRelayData(StreamTag::Dest, bytes);
}

void Socks5Session::OnDestSend(DWORD bytes, DWORD error) {
    destIo_.sending = false;
    if (error != 0) {
        Close();
        return;
    }
    {
        std::lock_guard lock(mutex_);
        if (!destIo_.sendQueue.empty()) {
            destIo_.sendFrontOffset += static_cast<size_t>(bytes);
            auto& front = destIo_.sendQueue.front();
            if (destIo_.sendFrontOffset >= front.size()) {
                destIo_.sendQueue.pop_front();
                destIo_.sendFrontOffset = 0;
            }
        }
    }
    PumpSend(StreamTag::Dest);

    MaybeResumeRelayRead(StreamTag::Client);
}

bool Socks5Session::TryPostRelayRead(StreamTag receiver) {
    if (state_ != SessionState::Relaying || closed_) return false;

    StreamIo& recvIo = receiver == StreamTag::Client ? clientIo_ : destIo_;
    StreamIo& sendIo = receiver == StreamTag::Client ? destIo_ : clientIo_;
    SOCKET sock = receiver == StreamTag::Client ? client_ : dest_;

    if (recvIo.reading || recvIo.peerClosed || recvIo.relayReadPaused || sock == INVALID_SOCKET) {
        return false;
    }

    {
        std::lock_guard lock(mutex_);
        if (sendIo.sendQueue.size() >= kMaxRelayQueueDepth) {
            recvIo.relayReadPaused = true;
            return false;
        }
    }

    recvIo.reading = true;
    if (!iocp_.PostRecv(sock, &recvIo.recvCtx, shared_from_this())) {
        recvIo.reading = false;
        Close();
        return false;
    }
    return true;
}

void Socks5Session::MaybeResumeRelayRead(StreamTag receiver) {
    if (state_ != SessionState::Relaying || closed_) return;

    StreamIo& recvIo = receiver == StreamTag::Client ? clientIo_ : destIo_;
    StreamIo& sendIo = receiver == StreamTag::Client ? destIo_ : clientIo_;

    if (!recvIo.relayReadPaused) return;

    {
        std::lock_guard lock(mutex_);
        if (sendIo.sendQueue.size() >= kMaxRelayQueueDepth) {
            return;
        }
        recvIo.relayReadPaused = false;
    }

    TryPostRelayRead(receiver);
}

void Socks5Session::OnRelayData(StreamTag from, size_t bytes) {
    StreamIo& srcIo = from == StreamTag::Client ? clientIo_ : destIo_;

    std::vector<char> chunk;
    chunk.swap(srcIo.recvCtx.buffer);
    chunk.resize(bytes);
    srcIo.recvCtx.buffer.resize(static_cast<size_t>(NetworkConfiguration::BufferSize));

    if (from == StreamTag::Client) {
        if (gssProtectActive_) {
            if (chunk.size() > kMaxProtocolBuffered ||
                ingest_.size() > kMaxProtocolBuffered - chunk.size()) {
                Close();
                return;
            }
            ingest_.insert(ingest_.end(), chunk.begin(), chunk.end());
            if (!ProcessGssRelayInput()) {
                Close();
                return;
            }
        } else {
            QueueDestSend(std::move(chunk));
        }
        TryPostRelayRead(StreamTag::Client);
    } else {
        if (gssProtectActive_) {
            for (size_t offset = 0; offset < chunk.size(); offset += kGssRelayChunk) {
                const size_t count = (std::min)(kGssRelayChunk, chunk.size() - offset);
                std::vector<char> part(chunk.begin() + static_cast<std::ptrdiff_t>(offset),
                                       chunk.begin() + static_cast<std::ptrdiff_t>(offset + count));
                if (!WrapAndQueueClient(part)) {
                    Close();
                    return;
                }
            }
        } else {
            QueueClientSendRaw(std::move(chunk));
        }
        TryPostRelayRead(StreamTag::Dest);
    }
}

void Socks5Session::QueueClientSendRaw(std::vector<char> data) {
    {
        std::lock_guard lock(mutex_);
        clientIo_.sendQueue.push_back(std::move(data));
    }
    PumpSend(StreamTag::Client);
}

void Socks5Session::QueueClientSend(std::vector<char> data) {
    if (gssProtectActive_ &&
        state_ != SessionState::Relaying &&
        state_ != SessionState::UdpAssociate) {
        if (!WrapAndQueueClient(data)) {
            Logger::Instance().Warning("GSSAPI: failed to wrap outbound SOCKS message.");
            Close();
        }
        return;
    }
    QueueClientSendRaw(std::move(data));
}

bool Socks5Session::WrapAndQueueClient(const std::vector<char>& cleartext) {
    if (!gssapi_) return false;
    const bool conf = gssapi_->ProtectionLevel() == socks5::Gssapi::ProtectConfidentiality ||
                      (gssapi_->ProtectionLevel() == socks5::Gssapi::ProtectSelective &&
                       gssapi_->ConfidentialityAvailable());
    std::vector<uint8_t> token;
    if (!gssapi_->Wrap(reinterpret_cast<const uint8_t*>(cleartext.data()), cleartext.size(), conf, token)) {
        return false;
    }
    if (token.size() > 65535) {
        return false;
    }
    SendGssFrame(socks5::Gssapi::MsgEncapsulated, token.data(), token.size());
    return true;
}

void Socks5Session::SendGssFrame(uint8_t mtyp, const uint8_t* token, size_t tokenLen) {
    std::vector<char> frame(4 + tokenLen);
    frame[0] = static_cast<char>(socks5::Gssapi::Version);
    frame[1] = static_cast<char>(mtyp);
    frame[2] = static_cast<char>((tokenLen >> 8) & 0xFF);
    frame[3] = static_cast<char>(tokenLen & 0xFF);
    if (tokenLen > 0 && token) {
        std::memcpy(frame.data() + 4, token, tokenLen);
    }
    QueueClientSendRaw(std::move(frame));
}

void Socks5Session::SendGssAbort() {
    QueueClientSendRaw({static_cast<char>(socks5::Gssapi::Version),
                        static_cast<char>(socks5::Gssapi::MsgAbort)});
}

int Socks5Session::TryReadGssFrame(uint8_t expectedMtyp, std::vector<uint8_t>& token) {
    token.clear();
    if (!ReadExactAvailable(2)) return 0;
    if (static_cast<uint8_t>(ingest_[0]) != socks5::Gssapi::Version) return -1;
    const uint8_t mtyp = static_cast<uint8_t>(ingest_[1]);
    if (mtyp == socks5::Gssapi::MsgAbort) {
        ingest_.erase(ingest_.begin(), ingest_.begin() + 2);
        return -1;
    }
    if (mtyp != expectedMtyp) return -1;
    if (!ReadExactAvailable(4)) return 0;
    const size_t len = (static_cast<size_t>(static_cast<uint8_t>(ingest_[2])) << 8) |
                       static_cast<size_t>(static_cast<uint8_t>(ingest_[3]));
    if (!ReadExactAvailable(4 + len)) return 0;
    token.assign(reinterpret_cast<uint8_t*>(ingest_.data() + 4),
                 reinterpret_cast<uint8_t*>(ingest_.data() + 4 + len));
    ingest_.erase(ingest_.begin(), ingest_.begin() + static_cast<std::ptrdiff_t>(4 + len));
    return 1;
}

bool Socks5Session::ProcessGssRelayInput() {
    while (!ingest_.empty()) {
        std::vector<uint8_t> token;
        const int result = TryReadGssFrame(socks5::Gssapi::MsgEncapsulated, token);
        if (result == 0) {
            return true;
        }
        if (result < 0) {
            return false;
        }

        std::vector<uint8_t> clear;
        if (!gssapi_ || !gssapi_->Unwrap(token.data(), token.size(), clear)) {
            return false;
        }
        if (!clear.empty()) {
            QueueDestSend(std::vector<char>(
                reinterpret_cast<const char*>(clear.data()),
                reinterpret_cast<const char*>(clear.data()) + clear.size()));
        }
    }
    return true;
}

bool Socks5Session::EnsureCleartextRequestIngest() {
    if (!gssProtectActive_ || gssRequestUnwrapped_) return true;
    std::vector<uint8_t> token;
    const int r = TryReadGssFrame(socks5::Gssapi::MsgEncapsulated, token);
    if (r == 0) return true;
    if (r < 0) return false;
    std::vector<uint8_t> clear;
    if (!gssapi_ || !gssapi_->Unwrap(token.data(), token.size(), clear)) {
        Logger::Instance().Warning("GSSAPI: failed to unwrap SOCKS request.");
        return false;
    }
    ingest_.insert(ingest_.begin(),
                   reinterpret_cast<const char*>(clear.data()),
                   reinterpret_cast<const char*>(clear.data()) + clear.size());
    gssRequestUnwrapped_ = true;
    return true;
}

void Socks5Session::QueueDestSend(std::vector<char> data) {
    {
        std::lock_guard lock(mutex_);
        destIo_.sendQueue.push_back(std::move(data));
    }
    PumpSend(StreamTag::Dest);
}

void Socks5Session::PumpSend(StreamTag tag) {
    StreamIo& io = (tag == StreamTag::Client) ? clientIo_ : destIo_;
    SOCKET sock = (tag == StreamTag::Client) ? client_ : dest_;
    if (sock == INVALID_SOCKET) return;

    std::lock_guard lock(mutex_);
    if (io.sending || io.sendQueue.empty()) return;

    auto& front = io.sendQueue.front();
    const size_t offset = io.sendFrontOffset;
    const size_t len = front.size() - offset;
    io.sending = true;
    if (!iocp_.PostSend(sock, &io.sendCtx, front.data(), offset, len, shared_from_this())) {
        io.sending = false;
        Close();
    }
}

bool Socks5Session::ReadExactAvailable(size_t need) {
    return ingest_.size() >= need;
}

bool Socks5Session::ProcessHandshakeBuffer() {
    if (!ReadExactAvailable(2)) return true;
    if (static_cast<uint8_t>(ingest_[0]) != socks5::kVersion) {
        const uint8_t firstByte = static_cast<uint8_t>(ingest_[0]);
        Logger::Instance().Warning("Unsupported SOCKS version: {Version}. {Hint}",
                                   static_cast<int>(firstByte),
                                   DescribeNonSocks5FirstByte(firstByte));
        return false;
    }
    const uint8_t methodCount = static_cast<uint8_t>(ingest_[1]);
    if (methodCount == 0) return false;
    if (!ReadExactAvailable(static_cast<size_t>(2) + static_cast<size_t>(methodCount))) return true;

    bool offerGss = false;
    bool offerUserPass = false;
    bool offerNoAuth = false;
    for (uint8_t i = 0; i < methodCount; ++i) {
        const uint8_t m = static_cast<uint8_t>(ingest_[static_cast<size_t>(2) + static_cast<size_t>(i)]);
        if (m == socks5::AuthMethod::Gssapi) offerGss = true;
        else if (m == socks5::AuthMethod::UsernamePassword) offerUserPass = true;
        else if (m == socks5::AuthMethod::NoAuth) offerNoAuth = true;
    }

    const bool hasCreds = NetworkConfiguration::HasCredentials();
    uint8_t selected = socks5::AuthMethod::NoAcceptableMethods;
    if (NetworkConfiguration::EnableGssapi && offerGss) {
        selected = socks5::AuthMethod::Gssapi;
    } else if (hasCreds && offerUserPass) {
        selected = socks5::AuthMethod::UsernamePassword;
    } else if (!hasCreds && offerNoAuth) {
        selected = socks5::AuthMethod::NoAuth;
    }

    ingest_.erase(ingest_.begin(), ingest_.begin() + 2 + methodCount);

    std::vector<char> reply = {static_cast<char>(socks5::kVersion), static_cast<char>(selected)};
    QueueClientSendRaw(std::move(reply));

    if (selected == socks5::AuthMethod::NoAcceptableMethods) {
        Logger::Instance().Warning(
            "Client does not support acceptable authentication methods (GSSAPI / UsernamePassword / NoAuth).");
        return false;
    }
    if (selected == socks5::AuthMethod::Gssapi) {
        gssapi_ = std::make_unique<GssapiContext>();
        if (!gssapi_->AcquireDefaultCredentials()) {
            SendGssAbort();
            return false;
        }
        state_ = SessionState::GssapiAuth;
    } else if (selected == socks5::AuthMethod::UsernamePassword) {
        state_ = SessionState::Auth;
    } else {
        state_ = SessionState::Request;
        Logger::Instance().Debug("Handshake completed successfully.");
    }
    return true;
}

bool Socks5Session::ProcessAuthBuffer() {
    if (!ReadExactAvailable(2)) return true;
    if (static_cast<uint8_t>(ingest_[0]) != socks5::AuthProtocol::Version) return false;
    const uint8_t ulen = static_cast<uint8_t>(ingest_[1]);
    const size_t ulenSize = static_cast<size_t>(ulen);
    if (!ReadExactAvailable(static_cast<size_t>(2) + ulenSize + 1)) return true;
    const uint8_t plen = static_cast<uint8_t>(ingest_[static_cast<size_t>(2) + ulenSize]);
    const size_t plenSize = static_cast<size_t>(plen);
    if (!ReadExactAvailable(static_cast<size_t>(2) + ulenSize + 1 + plenSize)) return true;

    const std::string username(ingest_.data() + 2, ulen);
    const std::string password(ingest_.data() + 3 + ulenSize, plen);
    ingest_.erase(ingest_.begin(),
                  ingest_.begin() + static_cast<std::ptrdiff_t>(static_cast<size_t>(2) + ulenSize + 1 + plenSize));

    const bool ok = ConstantTimeEqual(username, NetworkConfiguration::Username) &&
                    ConstantTimeEqual(password, NetworkConfiguration::Password);
    QueueClientSendRaw({static_cast<char>(socks5::AuthProtocol::Version),
                        static_cast<char>(ok ? socks5::AuthProtocol::Success
                                             : socks5::AuthProtocol::Failure)});
    if (!ok) {
        Logger::Instance().Warning("Username/Password authentication failed for client.");
        return false;
    }
    state_ = SessionState::Request;
    Logger::Instance().Debug("Handshake completed successfully.");
    return true;
}

bool Socks5Session::ProcessGssapiAuthBuffer() {
    std::vector<uint8_t> token;
    const int r = TryReadGssFrame(socks5::Gssapi::MsgAuth, token);
    if (r == 0) return true;
    if (r < 0) {
        SendGssAbort();
        return false;
    }

    if (!gssapi_) {
        SendGssAbort();
        return false;
    }

    std::vector<uint8_t> outToken;
    const auto status = gssapi_->AcceptToken(token.data(), token.size(), outToken);
    if (status == GssapiContext::AcceptStatus::Failed) {
        SendGssAbort();
        return false;
    }
    if (outToken.size() > 65535) {
        SendGssAbort();
        return false;
    }

    // RFC 1961: always reply with auth message; zero-length token is allowed when complete.
    SendGssFrame(socks5::Gssapi::MsgAuth, outToken.data(), outToken.size());

    if (status == GssapiContext::AcceptStatus::Complete) {
        if (!gssapi_->ClientName().empty()) {
            Logger::Instance().Info("GSSAPI authentication succeeded for {User}.", gssapi_->ClientName());
        } else {
            Logger::Instance().Info("GSSAPI authentication succeeded.");
        }
        state_ = SessionState::GssapiProtect;
    }
    return true;
}

bool Socks5Session::ProcessGssapiProtectBuffer() {
    std::vector<uint8_t> token;
    const int r = TryReadGssFrame(socks5::Gssapi::MsgProtection, token);
    if (r == 0) return true;
    if (r < 0) {
        SendGssAbort();
        return false;
    }

    std::vector<uint8_t> clear;
    if (!gssapi_ || !gssapi_->Unwrap(token.data(), token.size(), clear) || clear.empty()) {
        Logger::Instance().Warning("GSSAPI: invalid protection-level token.");
        SendGssAbort();
        return false;
    }

    const uint8_t clientLevel = clear[0];
    if (clientLevel < socks5::Gssapi::ProtectIntegrity ||
        clientLevel > socks5::Gssapi::ProtectSelective) {
        SendGssAbort();
        return false;
    }

    uint8_t selected = clientLevel;
    const int maxLevel = NetworkConfiguration::GssapiMaxProtection;
    if (selected > static_cast<uint8_t>(maxLevel)) {
        selected = static_cast<uint8_t>(maxLevel);
    }
    if (selected == socks5::Gssapi::ProtectConfidentiality && !gssapi_->ConfidentialityAvailable()) {
        selected = socks5::Gssapi::ProtectIntegrity;
    }
    if (selected == socks5::Gssapi::ProtectIntegrity && !gssapi_->IntegrityAvailable()) {
        // Still try integrity wrap; some packages omit the ret flag.
        selected = socks5::Gssapi::ProtectIntegrity;
    }

    gssapi_->SetProtectionLevel(selected);
    const uint8_t levelByte = selected;
    std::vector<uint8_t> wrapped;
    if (!gssapi_->Wrap(&levelByte, 1, false, wrapped)) {
        SendGssAbort();
        return false;
    }
    if (wrapped.size() > 65535) {
        SendGssAbort();
        return false;
    }
    SendGssFrame(socks5::Gssapi::MsgProtection, wrapped.data(), wrapped.size());

    gssProtectActive_ = true;
    gssRequestUnwrapped_ = false;
    state_ = SessionState::Request;
    Logger::Instance().Debug("GSSAPI protection level {Level} agreed; handshake completed.",
                             static_cast<int>(selected));
    return true;
}

bool Socks5Session::ProcessRequestBuffer() {
    if (gssProtectActive_) {
        if (!EnsureCleartextRequestIngest()) return false;
        if (!gssRequestUnwrapped_) return true;
    }

    if (!ReadExactAvailable(4)) return true;
    if (static_cast<uint8_t>(ingest_[0]) != socks5::kVersion ||
        static_cast<uint8_t>(ingest_[2]) != socks5::kReserved) {
        FailAndClose(socks5::ReplyCode::GeneralFailure);
        return true;
    }

    const uint8_t command = static_cast<uint8_t>(ingest_[1]);
    const uint8_t atyp = static_cast<uint8_t>(ingest_[3]);

    size_t need = 4;
    std::string address;
    uint16_t port = 0;

    if (atyp == socks5::AddressType::IPv4) {
        need += 6;
        if (!ReadExactAvailable(need)) return true;
        char ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, ingest_.data() + 4, ip, sizeof(ip));
        address = ip;
        port = static_cast<uint16_t>((static_cast<uint8_t>(ingest_[8]) << 8) |
                                     static_cast<uint8_t>(ingest_[9]));
    } else if (atyp == socks5::AddressType::IPv6) {
        need += 18;
        if (!ReadExactAvailable(need)) return true;
        char ip[INET6_ADDRSTRLEN]{};
        inet_ntop(AF_INET6, ingest_.data() + 4, ip, sizeof(ip));
        address = ip;
        port = static_cast<uint16_t>((static_cast<uint8_t>(ingest_[20]) << 8) |
                                     static_cast<uint8_t>(ingest_[21]));
    } else if (atyp == socks5::AddressType::DomainName) {
        if (!ReadExactAvailable(5)) return true;
        const uint8_t dlen = static_cast<uint8_t>(ingest_[4]);
        if (dlen == 0) {
            FailAndClose(socks5::ReplyCode::AddressTypeNotSupported);
            return true;
        }
        const size_t dlenSize = static_cast<size_t>(dlen);
        need = static_cast<size_t>(5) + dlenSize + static_cast<size_t>(2);
        if (!ReadExactAvailable(need)) return true;
        address.assign(ingest_.data() + 5, dlen);
        const size_t portOffset = static_cast<size_t>(5) + dlenSize;
        port = static_cast<uint16_t>((static_cast<uint16_t>(static_cast<uint8_t>(ingest_[portOffset])) << 8) |
                                     static_cast<uint8_t>(ingest_[portOffset + 1]));
    } else {
        FailAndClose(socks5::ReplyCode::AddressTypeNotSupported);
        return true;
    }

    ingest_.erase(ingest_.begin(), ingest_.begin() + static_cast<std::ptrdiff_t>(need));

    Logger::Instance().Debug("SOCKS5 request received: CMD=0x{Command:X2}, ATYP=0x{AddressType:X2}.",
                             static_cast<int>(command), static_cast<int>(atyp));
    Logger::Instance().Debug("Parsed destination: {Address}:{Port}, CMD=0x{Command:X2}.",
                             address, port, static_cast<int>(command));

    if (command == socks5::Command::Connect) {
        return StartConnect(address, port);
    }
    if (command == socks5::Command::UdpAssociate) {
        try {
            Logger::Instance().Info("Setting up UDP ASSOCIATE.");
            auto self = std::static_pointer_cast<Socks5Session>(shared_from_this());
            std::weak_ptr<Socks5Session> weakSelf = self;
            udpRelay_ = std::make_shared<UdpRelay>(
                iocp_, dns_, clientEp_, clientLocalEp_, resolver_,
                [weakSelf] {
                    if (auto session = weakSelf.lock()) {
                        session->iocp_.PostUser(session, &session->udpStopCtx_);
                    }
                });
            if (!udpRelay_->Start()) {
                FailAndClose(socks5::ReplyCode::GeneralFailure);
                return true;
            }
            CancelIdleTimer();
            SendSocksReply(socks5::ReplyCode::Succeeded, &udpRelay_->AdvertisedEndPoint());
            Logger::Instance().Info(
                "UDP ASSOCIATE setup completed, relay listening on {UdpEndPoint}{Friendly}.",
                NetworkUtils::EndpointToString(reinterpret_cast<const sockaddr*>(&udpRelay_->AdvertisedEndPoint())),
                resolver_.FriendlySuffix(reinterpret_cast<const sockaddr*>(&udpRelay_->AdvertisedEndPoint())));
            state_ = SessionState::UdpAssociate;
            BeginClientRead();
            return true;
        } catch (...) {
            FailAndClose(socks5::ReplyCode::GeneralFailure);
            return true;
        }
    }

    Logger::Instance().Warning("Unsupported command received: CMD=0x{Command:X2}, replying with code 0x{ReplyCode:X2}.",
                               static_cast<int>(command),
                               static_cast<int>(socks5::ReplyCode::CommandNotSupported));
    FailAndClose(socks5::ReplyCode::CommandNotSupported);
    return true;
}

bool Socks5Session::StartConnect(const std::string& address, uint16_t port) {
    const std::string clientEp = NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&clientEp_));
    const std::string friendly = resolver_.FriendlySuffix(reinterpret_cast<sockaddr*>(&clientEp_));
    Logger::Instance().Info("Connecting to {Address}:{Port} for client {ClientEndPoint}{Friendly}.",
                            address, port, clientEp, friendly);

    sockaddr_storage destStorage{};
    int destFamily = 0;
    if (NetworkUtils::ParseIP(address, destStorage, destFamily)) {
        return ConnectToHost(address, address, port);
    }

    state_ = SessionState::Resolving;
    pendingHost_ = address;
    pendingPort_ = port;
    dnsResult_.reset();
    CancelIdleTimer();

    auto self = std::static_pointer_cast<Socks5Session>(shared_from_this());
    dns_.ResolveAsync(address, [self](std::optional<std::string> ip) {
        std::lock_guard completionLock(self->completionMutex_);
        if (self->closed_) return;
        self->dnsResult_ = std::move(ip);
        if (!self->iocp_.PostUser(self, &self->dnsCtx_)) {
            self->Close();
        }
    });
    return true;
}

void Socks5Session::OnDnsResolved() {
    if (closed_ || state_ != SessionState::Resolving) {
        return;
    }

    if (!dnsResult_) {
        Logger::Instance().Error("Cannot connect: DNS did not resolve {Domain}.", pendingHost_);
        FailAndClose(socks5::ReplyCode::HostUnreachable);
        return;
    }

    const std::string destinationIP = *dnsResult_;
    sockaddr_storage destStorage{};
    int destFamily = 0;
    if (!NetworkUtils::ParseIP(destinationIP, destStorage, destFamily)) {
        FailAndClose(socks5::ReplyCode::HostUnreachable);
        return;
    }
    if (destFamily != NetworkConfiguration::OutputAddressFamily &&
        !NetworkUtils::IsAnyAddress(NetworkConfiguration::OutputInterfaceIP)) {
        Logger::Instance().Warning(
            "Resolved IP {ResolvedIP} is not compatible with output interface {OutputIP}.",
            destinationIP, NetworkConfiguration::OutputInterfaceIP);
        FailAndClose(socks5::ReplyCode::HostUnreachable);
        return;
    }

    if (!ConnectToHost(pendingHost_, destinationIP, pendingPort_)) {
        RequestCloseAfterFlush();
    }
}

bool Socks5Session::ConnectToHost(const std::string& address, const std::string& destinationIP, uint16_t port) {
    sockaddr_storage destStorage{};
    int destFamily = 0;
    if (!NetworkUtils::ParseIP(destinationIP, destStorage, destFamily)) {
        FailAndClose(socks5::ReplyCode::HostUnreachable);
        return false;
    }

    if (destFamily == AF_INET) {
        reinterpret_cast<sockaddr_in*>(&destStorage)->sin_port = htons(port);
    } else {
        reinterpret_cast<sockaddr_in6*>(&destStorage)->sin6_port = htons(port);
    }

    dest_ = IocpService::CreateTcpSocket(destFamily);
    if (dest_ == INVALID_SOCKET) {
        FailAndClose(socks5::ReplyCode::GeneralFailure);
        return false;
    }
    ConfigureSocket(dest_);

    sockaddr_storage bindAddr{};
    int bindLen = 0;
    if (!NetworkConfiguration::FillOutputBindAddress(bindAddr, bindLen) ||
        bind(dest_, reinterpret_cast<sockaddr*>(&bindAddr), bindLen) != 0) {
        closesocket(dest_);
        dest_ = INVALID_SOCKET;
        FailAndClose(socks5::ReplyCode::NetworkUnreachable);
        return false;
    }

    if (!iocp_.Associate(dest_, shared_from_this())) {
        closesocket(dest_);
        dest_ = INVALID_SOCKET;
        FailAndClose(socks5::ReplyCode::GeneralFailure);
        return false;
    }

    state_ = SessionState::Connecting;
    CancelIdleTimer();
    {
        const std::string meta = address + "\n" + destinationIP + "\n" + std::to_string(port);
        connectCtx_.buffer.assign(meta.begin(), meta.end());
        connectCtx_.buffer.push_back('\0');
    }

    const int addrLen = destFamily == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (!iocp_.PostConnect(dest_, &connectCtx_, reinterpret_cast<sockaddr*>(&destStorage), addrLen, shared_from_this())) {
        closesocket(dest_);
        dest_ = INVALID_SOCKET;
        FailAndClose(socks5::ReplyCode::GeneralFailure);
        return false;
    }
    if (!ArmConnectTimer()) {
        FailAndClose(socks5::ReplyCode::GeneralFailure);
        return false;
    }
    return true;
}

void Socks5Session::OnDestConnect(DWORD error) {
    CancelConnectTimer();
    if (state_ != SessionState::Connecting) {
        return;
    }
    if (error != 0) {
        uint8_t code = socks5::ReplyCode::GeneralFailure;
        if (error == WSAETIMEDOUT) code = socks5::ReplyCode::TtlExpired;
        else if (error == WSAECONNREFUSED) code = socks5::ReplyCode::ConnectionRefused;
        else if (error == WSAENETUNREACH) code = socks5::ReplyCode::NetworkUnreachable;
        else if (error == WSAEHOSTUNREACH) code = socks5::ReplyCode::HostUnreachable;
        Logger::Instance().Warning("Failed to connect.");
        if (dest_ != INVALID_SOCKET) {
            closesocket(dest_);
            dest_ = INVALID_SOCKET;
        }
        FailAndClose(code);
        return;
    }

    sockaddr_storage local{};
    int localLen = sizeof(local);
    getsockname(dest_, reinterpret_cast<sockaddr*>(&local), &localLen);
    SendSocksReply(socks5::ReplyCode::Succeeded, &local);

    std::string address = "?";
    std::string resolved = "?";
    uint16_t port = 0;
    if (!connectCtx_.buffer.empty()) {
        std::string meta(connectCtx_.buffer.data());
        const size_t p1 = meta.find('\n');
        const size_t p2 = meta.find('\n', p1 == std::string::npos ? p1 : p1 + 1);
        if (p1 != std::string::npos && p2 != std::string::npos) {
            address = meta.substr(0, p1);
            resolved = meta.substr(p1 + 1, p2 - p1 - 1);
            port = static_cast<uint16_t>(std::stoi(meta.substr(p2 + 1)));
        }
    }

    const std::string clientEp = NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&clientEp_));
    const std::string friendly = resolver_.FriendlySuffix(reinterpret_cast<sockaddr*>(&clientEp_));
    Logger::Instance().Info("Connected to {Address}:{Port} ({ResolvedIP}) for client {ClientEndPoint}{Friendly}.",
                            address, port, resolved, clientEp, friendly);

    StartRelay();
}

void Socks5Session::StartRelay() {
    state_ = SessionState::Relaying;
    CancelIdleTimer();
    Logger::Instance().Debug("Starting data forwarding.");

    if (!ingest_.empty()) {
        if (gssProtectActive_) {
            if (!ProcessGssRelayInput()) {
                Close();
                return;
            }
        } else {
            std::vector<char> pipelined;
            pipelined.swap(ingest_);
            QueueDestSend(std::move(pipelined));
        }
    }

    if (!clientIo_.reading) {
        BeginClientRead();
    }
    destIo_.reading = true;
    if (!iocp_.PostRecv(dest_, &destIo_.recvCtx, shared_from_this())) {
        destIo_.reading = false;
        Close();
    }
}

bool Socks5Session::SendSocksReply(uint8_t replyCode, const sockaddr_storage* bound) {
    std::vector<char> buffer(22);
    int offset = 0;
    buffer[offset++] = static_cast<char>(socks5::kVersion);
    buffer[offset++] = static_cast<char>(replyCode);
    buffer[offset++] = static_cast<char>(socks5::kReserved);

    if (!bound) {
        buffer[offset++] = static_cast<char>(socks5::AddressType::IPv4);
        std::memset(buffer.data() + offset, 0, 6);
        offset += 6;
    } else if (bound->ss_family == AF_INET) {
        buffer[offset++] = static_cast<char>(socks5::AddressType::IPv4);
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(bound);
        std::memcpy(buffer.data() + offset, &v4->sin_addr, 4);
        offset += 4;
        const uint16_t port = ntohs(v4->sin_port);
        buffer[offset++] = static_cast<char>(port >> 8);
        buffer[offset++] = static_cast<char>(port & 0xFF);
    } else {
        buffer[offset++] = static_cast<char>(socks5::AddressType::IPv6);
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(bound);
        std::memcpy(buffer.data() + offset, &v6->sin6_addr, 16);
        offset += 16;
        const uint16_t port = ntohs(v6->sin6_port);
        buffer[offset++] = static_cast<char>(port >> 8);
        buffer[offset++] = static_cast<char>(port & 0xFF);
    }

    buffer.resize(static_cast<size_t>(offset));
    QueueClientSend(std::move(buffer));
    return true;
}
