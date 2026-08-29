#pragma once

#include "../../dns/DnsResolver.h"
#include "GssapiContext.h"
#include "UdpRelay.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

class ProxyServer;

enum class SessionState : uint8_t {
    Handshake,
    Auth,
    GssapiAuth,
    GssapiProtect,
    Request,
    Resolving,
    Connecting,
    Relaying,
    UdpAssociate,
    Closing
};

class Socks5Session : public IocpHandle {
public:
    Socks5Session(IocpService& iocp,
                  ProxyServer& server,
                  SOCKET client,
                  DnsResolver& dns,
                  FriendlyNameResolver& resolver,
                  bool slotHeld);
    ~Socks5Session() override;

    bool Start();
    void Close();
    void OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) override;

private:
    enum class StreamTag : uint8_t { Client, Dest };

    static constexpr uint64_t kTimerConnect = 2;
    static constexpr uint64_t kTimerIdle = 3;

    struct StreamIo {
        IoContext recvCtx;
        IoContext sendCtx;
        std::deque<std::vector<char>> sendQueue;
        size_t sendFrontOffset = 0;
        bool sending = false;
        bool reading = false;
        bool peerClosed = false;
        bool relayReadPaused = false;
        explicit StreamIo(size_t recvBufSize)
            : recvCtx(IoOp::Recv, recvBufSize), sendCtx(IoOp::Send, 0) {}
    };

    void ConfigureSocket(SOCKET s);
    bool BeginClientRead();
    void OnClientRecv(DWORD bytes, DWORD error);
    void OnClientSend(DWORD bytes, DWORD error);
    void OnDestRecv(DWORD bytes, DWORD error);
    void OnDestSend(DWORD bytes, DWORD error);
    void OnDestConnect(DWORD error);
    void OnDnsResolved();
    void OnTimer(uint64_t kind);

    bool ProcessHandshakeBuffer();
    bool ProcessAuthBuffer();
    bool ProcessGssapiAuthBuffer();
    bool ProcessGssapiProtectBuffer();
    bool ProcessRequestBuffer();
    bool StartConnect(const std::string& address, uint16_t port);
    bool ConnectToHost(const std::string& address, const std::string& destinationIP, uint16_t port);
    bool SendSocksReply(uint8_t replyCode, const sockaddr_storage* bound = nullptr);
    void QueueClientSend(std::vector<char> data);
    void QueueDestSend(std::vector<char> data);
    void QueueClientSendRaw(std::vector<char> data);
    void PumpSend(StreamTag tag);
    void StartRelay();
    void OnRelayData(StreamTag from, size_t bytes);
    void MaybeResumeRelayRead(StreamTag receiver);
    bool TryPostRelayRead(StreamTag receiver);
    bool ReadExactAvailable(size_t need);
    /// @return 1 = frame ready (token filled), 0 = need more data, -1 = protocol error
    int TryReadGssFrame(uint8_t expectedMtyp, std::vector<uint8_t>& token);
    void SendGssFrame(uint8_t mtyp, const uint8_t* token, size_t tokenLen);
    void SendGssAbort();
    bool WrapAndQueueClient(const std::vector<char>& cleartext);
    bool ProcessGssRelayInput();
    /// When GSS protection is active, unwrap one encapsulated SOCKS PDU into ingest_.
    bool EnsureCleartextRequestIngest();

    void ArmIdleTimer();
    void CancelIdleTimer();
    bool ArmConnectTimer();
    void CancelConnectTimer();
    void RequestCloseAfterFlush();
    void FailAndClose(uint8_t replyCode);
    void OnUdpRelayStopped();

    IocpService& iocp_;
    ProxyServer& server_;
    DnsResolver& dns_;
    FriendlyNameResolver& resolver_;

    SOCKET client_ = INVALID_SOCKET;
    SOCKET dest_ = INVALID_SOCKET;
    sockaddr_storage clientEp_{};
    sockaddr_storage clientLocalEp_{};

    SessionState state_ = SessionState::Handshake;
    std::atomic<bool> closed_{false};
    bool closeAfterFlush_ = false;

    StreamIo clientIo_;
    StreamIo destIo_;
    IoContext connectCtx_{IoOp::Connect};
    IoContext dnsCtx_{IoOp::User};
    IoContext udpStopCtx_{IoOp::User};

    IocpService::TimerId connectTimerId_ = 0;
    IocpService::TimerId idleTimerId_ = 0;
    uint64_t connectTimerGeneration_ = 0;
    uint64_t idleTimerGeneration_ = 0;

    std::string pendingHost_;
    uint16_t pendingPort_ = 0;
    std::optional<std::string> dnsResult_;

    std::vector<char> ingest_;
    std::mutex mutex_;

    std::shared_ptr<UdpRelay> udpRelay_;
    bool slotHeld_ = false;

    std::unique_ptr<GssapiContext> gssapi_;
    bool gssProtectActive_ = false;
    bool gssRequestUnwrapped_ = false;
};
