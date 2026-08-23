#pragma once

#include "Iocp.h"

#include <cstddef>
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
        static constexpr size_t kAddressBufferSize =
            2 * (sizeof(sockaddr_storage) + 16);

        IoContext ctx{IoOp::Accept, kAddressBufferSize};
        SOCKET acceptSocket = INVALID_SOCKET;
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
