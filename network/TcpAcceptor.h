#pragma once

#include "Iocp.h"

#include <functional>
#include <memory>
#include <vector>
#include <atomic>

/// Overlapped AcceptEx acceptor bound to an IOCP service.
class TcpAcceptor : public IocpHandle {
public:
    using AcceptCallback = std::function<void(SOCKET client)>;

    TcpAcceptor(IocpService& iocp, SOCKET listenSocket, int family, AcceptCallback onAccept);
    ~TcpAcceptor() override;

    bool Start(unsigned pendingAccepts = 16);
    void Stop();

    void OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) override;

private:
    struct AcceptIo {
        IoContext ctx;
        SOCKET acceptSocket = INVALID_SOCKET;
        // AcceptEx local+remote address block
        char addrBuf[2 * (sizeof(sockaddr_storage) + 16)]{};

        AcceptIo() : ctx(IoOp::Accept, 0) {}
    };

    bool PostAccept(AcceptIo& io);
    void HandleAccept(AcceptIo& io, DWORD error);

    IocpService& iocp_;
    SOCKET listenSocket_;
    int family_;
    AcceptCallback onAccept_;
    LPFN_ACCEPTEX acceptEx_ = nullptr;
    std::vector<std::unique_ptr<AcceptIo>> accepts_;
    std::atomic<bool> stopping_{false};
};
