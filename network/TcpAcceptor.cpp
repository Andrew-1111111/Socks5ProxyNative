#include "TcpAcceptor.h"

#include "Iocp.h"
#include "../utils/Logger.h"

#include <WinSock2.h>
#include <Windows.h>
#include <MSWSock.h>

#include <memory>
#include <mutex>
#include <utility>

TcpAcceptor::TcpAcceptor(IocpService& iocp, SOCKET listenSocket, int family, AcceptCallback onAccept)
    : iocp_(iocp),
      listenSocket_(listenSocket),
      family_(family),
      onAccept_(std::move(onAccept)) {}

TcpAcceptor::~TcpAcceptor() {
    Stop();
}

bool TcpAcceptor::Start(unsigned pendingAccepts) {
    if (!IocpService::LoadAcceptEx(listenSocket_, &acceptEx_) || !acceptEx_) {
        Logger::Instance().Error("Failed to load AcceptEx");
        return false;
    }

    if (!iocp_.Associate(listenSocket_, shared_from_this())) {
        Logger::Instance().Error("Failed to associate listen socket with IOCP");
        return false;
    }

    if (pendingAccepts == 0) pendingAccepts = 16;
    accepts_.reserve(pendingAccepts);
    for (unsigned i = 0; i < pendingAccepts; ++i) {
        accepts_.push_back(std::make_unique<AcceptIo>());
        if (!PostAccept(*accepts_.back())) {
            Logger::Instance().Error("Failed to post initial AcceptEx");
            return false;
        }
    }
    return true;
}

void TcpAcceptor::Stop() {
    std::lock_guard completionLock(completionMutex_);
    stopping_ = true;
}

bool TcpAcceptor::PostAccept(AcceptIo& io) {
    if (stopping_) return false;

    if (io.acceptSocket != INVALID_SOCKET) {
        closesocket(io.acceptSocket);
        io.acceptSocket = INVALID_SOCKET;
    }

    io.acceptSocket = IocpService::CreateTcpSocket(family_);
    if (io.acceptSocket == INVALID_SOCKET) {
        return false;
    }

    if (!iocp_.PostAccept(listenSocket_, io.acceptSocket, &io.ctx,
                          io.ctx.buffer.data(), static_cast<DWORD>(io.ctx.buffer.size()),
                          shared_from_this(), acceptEx_)) {
        closesocket(io.acceptSocket);
        io.acceptSocket = INVALID_SOCKET;
        return false;
    }
    return true;
}

void TcpAcceptor::OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) {
    (void)bytes;
    if (!ctx) return;

    AcceptIo* io = nullptr;
    for (auto& item : accepts_) {
        if (&item->ctx == ctx) {
            io = item.get();
            break;
        }
    }
    if (!io) return;

    HandleAccept(*io, error);
}

void TcpAcceptor::HandleAccept(AcceptIo& io, DWORD error) {
    SOCKET client = io.acceptSocket;
    io.acceptSocket = INVALID_SOCKET;

    if (stopping_) {
        if (client != INVALID_SOCKET) closesocket(client);
        return;
    }

    if (error != 0 || client == INVALID_SOCKET) {
        if (client != INVALID_SOCKET) closesocket(client);
        if (!stopping_ && !PostAccept(io)) {
            Logger::Instance().Error("Failed to repost AcceptEx after an accept error.");
        }
        return;
    }

    if (onAccept_) {
        onAccept_(client);
    } else {
        closesocket(client);
    }

    if (!stopping_ && !PostAccept(io)) {
        Logger::Instance().Error("Failed to repost AcceptEx.");
    }
}
