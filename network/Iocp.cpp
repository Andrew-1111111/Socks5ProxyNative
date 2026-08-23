#include "Iocp.h"

#include <algorithm>
#include <cstring>
#include <mutex>

LPFN_CONNECTEX IocpService::connectEx_ = nullptr;
std::once_flag IocpService::connectExInit_;

IoContext::IoContext(IoOp operation, size_t bufSize) : op(operation) {
    std::memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED));
    if (bufSize > 0) {
        buffer.resize(bufSize);
        wsaBuf.buf = buffer.data();
    }
    wsaBuf.len = static_cast<ULONG>(bufSize);
}

void IoContext::Reset(IoOp operation) {
    std::memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED));
    op = operation;
    flags = 0;
    sendOffset = 0;
    sendLength = 0;
    userKey = 0;
    addrLen = sizeof(addr);
}

bool IocpHandle::WaitPendingZero(int timeoutMs) const {
    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + std::chrono::milliseconds(timeoutMs < 0 ? 0 : timeoutMs);
    while (pending_.load(std::memory_order_acquire) > 0) {
        if (timeoutMs >= 0 && clock::now() >= deadline) {
            return false;
        }
        Sleep(1);
    }
    return true;
}

IocpService::IocpService(unsigned workerCount) {
    if (workerCount == 0) {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        workerCount = si.dwNumberOfProcessors * 2;
        if (workerCount < 2) workerCount = 2;
        if (workerCount > 32) workerCount = 32;
    }
    workerCount_ = workerCount;
}

IocpService::~IocpService() {
    Stop();
}

bool IocpService::Start() {
    if (running_.exchange(true)) {
        return true;
    }

    iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (!iocp_) {
        running_ = false;
        return false;
    }

    for (unsigned i = 0; i < workerCount_; ++i) {
        workers_.emplace_back([this] { WorkerLoop(); });
    }
    return true;
}

void IocpService::Stop() {
    if (!running_.exchange(false)) {
        return;
    }

    ClearTimers();

    for (unsigned i = 0; i < workers_.size(); ++i) {
        PostQueuedCompletionStatus(iocp_, 0, 0, nullptr);
    }
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();

    if (iocp_) {
        CloseHandle(iocp_);
        iocp_ = nullptr;
    }
}

void IocpService::ClearTimers() {
    std::vector<TimerEntry> doomed;
    {
        std::lock_guard lock(timerMutex_);
        for (auto& [id, e] : timers_) {
            doomed.push_back(e);
        }
        timers_.clear();
    }
    for (auto& e : doomed) {
        if (e.handle) e.handle->ReleasePending();
        delete e.ctx;
    }
}

bool IocpService::Associate(SOCKET socket, IocpHandle* handle) {
    if (!iocp_ || socket == INVALID_SOCKET || !handle) {
        return false;
    }
    return CreateIoCompletionPort(reinterpret_cast<HANDLE>(socket), iocp_,
                                  reinterpret_cast<ULONG_PTR>(handle), 0) != nullptr;
}

SOCKET IocpService::CreateTcpSocket(int family) {
    return WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
}

SOCKET IocpService::CreateUdpSocket(int family) {
    return WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
}

bool IocpService::BindAny(SOCKET socket, int family) {
    if (family == AF_INET) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = 0;
        return bind(socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    }
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = 0;
    return bind(socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
}

bool IocpService::LoadConnectEx(SOCKET socket, LPFN_CONNECTEX* outFn) {
    GUID guid = WSAID_CONNECTEX;
    DWORD bytes = 0;
    return WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &guid, sizeof(guid),
                    outFn, sizeof(*outFn),
                    &bytes, nullptr, nullptr) == 0;
}

bool IocpService::PostRecv(SOCKET socket, IoContext* ctx, IocpHandle* handle) {
    ctx->Reset(IoOp::Recv);
    ctx->socket = socket;
    ctx->wsaBuf.buf = ctx->buffer.data();
    ctx->wsaBuf.len = static_cast<ULONG>(ctx->buffer.size());
    ctx->flags = 0;
    handle->AddPending();
    DWORD recvd = 0;
    const int r = WSARecv(socket, &ctx->wsaBuf, 1, &recvd, &ctx->flags, ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        return false;
    }
    return true;
}

bool IocpService::PostSend(SOCKET socket, IoContext* ctx, size_t offset, size_t length, IocpHandle* handle) {
    if (!ctx || ctx->buffer.empty()) {
        return false;
    }
    return PostSend(socket, ctx, ctx->buffer.data(), offset, length, handle);
}

bool IocpService::PostSend(SOCKET socket, IoContext* ctx, char* data, size_t offset, size_t length,
                            IocpHandle* handle) {
    if (!data || length == 0) {
        return false;
    }
    ctx->Reset(IoOp::Send);
    ctx->socket = socket;
    ctx->sendOffset = offset;
    ctx->sendLength = length;
    ctx->wsaBuf.buf = data + offset;
    ctx->wsaBuf.len = static_cast<ULONG>(length);
    handle->AddPending();
    DWORD sent = 0;
    const int r = WSASend(socket, &ctx->wsaBuf, 1, &sent, 0, ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        return false;
    }
    return true;
}

bool IocpService::PostRecvFrom(SOCKET socket, IoContext* ctx, IocpHandle* handle) {
    ctx->Reset(IoOp::RecvFrom);
    ctx->socket = socket;
    ctx->wsaBuf.buf = ctx->buffer.data();
    ctx->wsaBuf.len = static_cast<ULONG>(ctx->buffer.size());
    ctx->flags = 0;
    ctx->addrLen = sizeof(ctx->addr);
    handle->AddPending();
    DWORD recvd = 0;
    const int r = WSARecvFrom(socket, &ctx->wsaBuf, 1, &recvd, &ctx->flags,
                              reinterpret_cast<sockaddr*>(&ctx->addr), &ctx->addrLen,
                              ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        return false;
    }
    return true;
}

bool IocpService::PostSendTo(SOCKET socket, IoContext* ctx, size_t length,
                             const sockaddr* to, int toLen, IocpHandle* handle) {
    if (!ctx || ctx->buffer.empty()) {
        return false;
    }
    return PostSendTo(socket, ctx, ctx->buffer.data(), length, to, toLen, handle);
}

bool IocpService::PostSendTo(SOCKET socket, IoContext* ctx, char* data, size_t length,
                             const sockaddr* to, int toLen, IocpHandle* handle) {
    if (!data || length == 0) {
        return false;
    }
    ctx->Reset(IoOp::SendTo);
    ctx->socket = socket;
    ctx->wsaBuf.buf = data;
    ctx->wsaBuf.len = static_cast<ULONG>(length);
    handle->AddPending();
    DWORD sent = 0;
    const int r = WSASendTo(socket, &ctx->wsaBuf, 1, &sent, 0, to, toLen, ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        return false;
    }
    return true;
}

bool IocpService::PostConnect(SOCKET socket, IoContext* ctx, const sockaddr* name, int namelen,
                              IocpHandle* handle) {
    std::call_once(connectExInit_, [] {
        SOCKET probe = CreateTcpSocket(AF_INET);
        if (probe != INVALID_SOCKET) {
            LoadConnectEx(probe, &connectEx_);
            closesocket(probe);
        }
    });
    if (!connectEx_) {
        return false;
    }

    ctx->Reset(IoOp::Connect);
    ctx->socket = socket;
    handle->AddPending();
    const BOOL ok = connectEx_(socket, name, namelen, nullptr, 0, nullptr, ctx);
    if (!ok && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        return false;
    }
    return true;
}

bool IocpService::LoadAcceptEx(SOCKET socket, LPFN_ACCEPTEX* outFn) {
    GUID guid = WSAID_ACCEPTEX;
    DWORD bytes = 0;
    return WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &guid, sizeof(guid),
                    outFn, sizeof(*outFn),
                    &bytes, nullptr, nullptr) == 0;
}

bool IocpService::PostAccept(SOCKET listenSocket, SOCKET acceptSocket, IoContext* ctx,
                             char* addrBuf, DWORD addrBufLen, IocpHandle* handle,
                             LPFN_ACCEPTEX acceptEx) {
    if (!acceptEx) return false;
    ctx->Reset(IoOp::Accept);
    ctx->socket = acceptSocket;
    handle->AddPending();
    DWORD bytes = 0;
    const BOOL ok = acceptEx(listenSocket, acceptSocket, addrBuf, 0,
                             addrBufLen / 2, addrBufLen / 2,
                             &bytes, ctx);
    if (!ok && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        return false;
    }
    return true;
}

bool IocpService::PostUser(IocpHandle* handle, IoContext* ctx, uint64_t userKey) {
    if (!running_ || !iocp_) {
        return false;
    }
    ctx->Reset(IoOp::User);
    ctx->userKey = userKey;
    handle->AddPending();
    if (!PostQueuedCompletionStatus(iocp_, 0, reinterpret_cast<ULONG_PTR>(handle), ctx)) {
        handle->ReleasePending();
        return false;
    }
    return true;
}

IocpService::TimerId IocpService::ScheduleTimeout(IocpHandle* handle, uint64_t userKey, int delayMs) {
    if (!running_ || !iocp_ || !handle || delayMs < 0) {
        return 0;
    }

    auto* ctx = new IoContext(IoOp::User, 0);
    ctx->userKey = userKey;
    handle->AddPending();

    TimerEntry entry;
    entry.id = nextTimerId_.fetch_add(1);
    if (entry.id == 0) {
        entry.id = nextTimerId_.fetch_add(1);
    }
    entry.due = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
    entry.handle = handle;
    entry.ctx = ctx;

    {
        std::lock_guard lock(timerMutex_);
        timers_.emplace(entry.id, entry);
    }

    PostQueuedCompletionStatus(iocp_, 0, 0, nullptr);
    return entry.id;
}

void IocpService::CancelTimeout(TimerId id) {
    if (id == 0) return;

    TimerEntry entry;
    bool found = false;
    {
        std::lock_guard lock(timerMutex_);
        auto it = timers_.find(id);
        if (it == timers_.end()) return;
        entry = it->second;
        timers_.erase(it);
        found = true;
    }
    if (found) {
        if (entry.handle) entry.handle->ReleasePending();
        delete entry.ctx;
    }
}

DWORD IocpService::AdvanceTimers() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<TimerEntry> due;
    DWORD waitMs = INFINITE;

    {
        std::lock_guard lock(timerMutex_);
        for (auto it = timers_.begin(); it != timers_.end();) {
            if (it->second.due <= now) {
                due.push_back(it->second);
                it = timers_.erase(it);
            } else {
                ++it;
            }
        }

        if (!timers_.empty()) {
            auto nearest = timers_.begin()->second.due;
            for (const auto& [id, e] : timers_) {
                if (e.due < nearest) nearest = e.due;
            }
            if (nearest <= now) {
                waitMs = 0;
            } else {
                const auto ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(nearest - now).count();
                if (ms <= 0) {
                    waitMs = 0;
                } else if (ms >= INFINITE - 1) {
                    waitMs = INFINITE - 1;
                } else {
                    waitMs = static_cast<DWORD>(ms);
                }
            }
        }
    }

    for (auto& e : due) {
        if (!PostQueuedCompletionStatus(iocp_, 0, reinterpret_cast<ULONG_PTR>(e.handle), e.ctx)) {
            if (e.handle) e.handle->ReleasePending();
            delete e.ctx;
        }
    }

    return waitMs;
}

void IocpService::WorkerLoop() {
    while (true) {
        const DWORD waitMs = AdvanceTimers();

        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* overlapped = nullptr;
        const BOOL ok = GetQueuedCompletionStatus(iocp_, &bytes, &key, &overlapped, waitMs);

        if (!ok && overlapped == nullptr) {
            const DWORD err = GetLastError();
            if (err == WAIT_TIMEOUT) {
                continue;
            }
            if (!running_) break;
            continue;
        }

        if (overlapped == nullptr && key == 0) {
            if (!running_) break;
            continue;
        }

        auto* handle = reinterpret_cast<IocpHandle*>(key);
        auto* ctx = static_cast<IoContext*>(overlapped);

        DWORD error = 0;
        if (!ok) {
            error = GetLastError();
            if (ctx && ctx->socket != INVALID_SOCKET) {
                DWORD transferred = 0;
                DWORD flags = 0;
                if (!WSAGetOverlappedResult(ctx->socket, ctx, &transferred, FALSE, &flags)) {
                    error = WSAGetLastError();
                }
                bytes = transferred;
            }
        }

        if (!handle) {
            continue;
        }

        std::shared_ptr<IocpHandle> pin;
        try {
            pin = handle->shared_from_this();
        } catch (...) {
            pin.reset();
        }
        // Object already destroyed or not owned by shared_ptr — do not touch it.
        if (!pin) {
            continue;
        }

        handle->OnIoCompleted(bytes, error, ctx);
        handle->ReleasePending();
    }
}
