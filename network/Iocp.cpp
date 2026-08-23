#include "Iocp.h"

#include <WinSock2.h>
#include <Windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <MSWSock.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

bool FitsULong(size_t value) {
    return value <= static_cast<size_t>(ULONG_MAX);
}
ULONG ToULong(size_t value) {
    return static_cast<ULONG>(value);
}

bool ValidExternalSendRange(size_t offset, size_t length) {
    if (length == 0 || !FitsULong(length)) {
        return false;
    }
    constexpr size_t maxSize = std::numeric_limits<size_t>::max();
    return offset <= maxSize - length;
}

bool ValidBufferSendRange(const std::vector<char>& buffer, size_t offset, size_t length) {
    if (!ValidExternalSendRange(offset, length)) {
        return false;
    }
    return offset <= buffer.size() && length <= buffer.size() - offset;
}

bool ValidRecvRange(const std::vector<char>& buffer, size_t offset, size_t length) {
    if (offset > buffer.size()) {
        return false;
    }
    const size_t available = buffer.size() - offset;
    const size_t recvLen = length == 0 ? available : length;
    if (recvLen == 0 || !FitsULong(recvLen)) {
        return false;
    }
    if (length != 0 && length > available) {
        return false;
    }
    return true;
}

bool ValidAcceptExAddrBuf(char* addrBuf, DWORD addrBufLen) {
    // AcceptEx stores local and remote address blocks; each needs sizeof(sockaddr)+16.
    constexpr DWORD kMinAddrBufLen = static_cast<DWORD>((sizeof(sockaddr_storage) + 16) * 2);
    return addrBuf != nullptr && addrBufLen >= kMinAddrBufLen && (addrBufLen % 2) == 0;
}

void BindContext(IoContext* ctx, const std::shared_ptr<IocpHandle>& handle) {
    ctx->handlePin = handle;
}

void CleanupClaimedContexts(std::vector<IoContext*>& claimed) {
    for (IoContext* ctx : claimed) {
        if (ctx && ctx->handlePin) {
            ctx->handlePin->ReleasePending();
        }
        if (ctx && ctx->iocpOwned) {
            delete ctx;
        }
    }
    claimed.clear();
}

std::atomic<LPFN_CONNECTEX> g_connectEx{nullptr};

}  // namespace

IoContext::IoContext(IoOp operation, size_t bufSize) : op(operation) {
    std::memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED));
    if (bufSize > 0) {
        buffer.resize(bufSize);
        wsaBuf.buf = buffer.data();
    }
    wsaBuf.len = ToULong(bufSize);
}

void IoContext::Reset(IoOp operation) {
    std::memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED));
    op = operation;
    flags = 0;
    sendOffset = 0;
    sendLength = 0;
    userKey = 0;
    iocpOwned = false;
    handlePin.reset();
    addrLen = sizeof(addr);
}

bool IocpHandle::WaitPendingZero(int timeoutMs) const {
    using clock = std::chrono::steady_clock;
    const std::chrono::steady_clock::time_point deadline =
        clock::now() + std::chrono::milliseconds(timeoutMs < 0 ? 0 : timeoutMs);
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
    std::unique_lock lock(lifecycleMutex_);
    if (stopping_.load(std::memory_order_acquire)) {
        return false;
    }
    if (running_.load(std::memory_order_acquire)) {
        return iocp_ != nullptr;
    }
    for (const std::thread& worker : workers_) {
        if (worker.joinable()) {
            return false;
        }
    }

    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (!iocp) {
        return false;
    }

    iocp_ = iocp;
    running_.store(true, std::memory_order_release);
    try {
        workers_.reserve(workerCount_);
        for (unsigned i = 0; i < workerCount_; ++i) {
            workers_.emplace_back([this] { WorkerLoop(); });
        }
    } catch (...) {
        running_.store(false, std::memory_order_release);
        stopping_.store(true, std::memory_order_release);
        for (size_t i = 0; i < workers_.size(); ++i) {
            PostQueuedCompletionStatus(iocp_, 0, 0, nullptr);
        }

        lock.unlock();
        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        lock.lock();

        workers_.clear();
        CloseHandle(iocp_);
        iocp_ = nullptr;
        stopping_.store(false, std::memory_order_release);
        return false;
    }

    return true;
}

void IocpService::Stop() {
    HANDLE iocpToClose = nullptr;

    {
        std::unique_lock lock(lifecycleMutex_);
        if (!running_.exchange(false, std::memory_order_acq_rel)) {
            return;
        }
        stopping_.store(true, std::memory_order_release);

        ClearTimers();

        iocpToClose = iocp_;
        if (iocpToClose) {
            for (unsigned i = 0; i < workers_.size(); ++i) {
                PostQueuedCompletionStatus(iocpToClose, 0, 0, nullptr);
            }
        }
    }

    for (std::thread& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    {
        std::unique_lock lock(lifecycleMutex_);
        if (iocp_ == iocpToClose) {
            iocp_ = nullptr;
        }
        workers_.clear();
    }

    WaitIocpIdle();

    if (iocpToClose) {
        CloseHandle(iocpToClose);
    }

    stopping_.store(false, std::memory_order_release);
}

IocpService::IocpLease::IocpLease(IocpService& svc) : svc_(svc) {
    std::shared_lock lock(svc_.lifecycleMutex_);
    if (!svc_.iocp_) {
        return;
    }
    handle_ = svc_.iocp_;
    svc_.PinIocpHandle();
}

IocpService::IocpLease::~IocpLease() {
    if (handle_) {
        svc_.UnpinIocpHandle();
    }
}

void IocpService::WaitIocpIdle() const {
    std::unique_lock lock(iocpIdleMutex_);
    iocpIdleCv_.wait(lock, [this] {
        return iocpUsers_.load(std::memory_order_acquire) == 0;
    });
}

void IocpService::PinIocpHandle() {
    iocpUsers_.fetch_add(1, std::memory_order_acq_rel);
}

void IocpService::UnpinIocpHandle() {
    const int prev = iocpUsers_.fetch_sub(1, std::memory_order_acq_rel);
    if (prev == 1) {
        std::lock_guard lock(iocpIdleMutex_);
        iocpIdleCv_.notify_all();
    }
}

bool IocpService::PostIocpCompletion(HANDLE iocp, DWORD bytes, ULONG_PTR key, OVERLAPPED* overlapped) {
    PinIocpHandle();
    const BOOL ok = PostQueuedCompletionStatus(iocp, bytes, key, overlapped);
    UnpinIocpHandle();
    return ok != FALSE;
}

void IocpService::ClearTimers() {
    std::vector<std::shared_ptr<TimerState>> doomed;
    {
        std::lock_guard lock(timerMutex_);
        for (std::unordered_map<TimerId, std::shared_ptr<TimerState>>::iterator it = timers_.begin();
             it != timers_.end(); ++it) {
            doomed.push_back(std::move(it->second));
        }
        timers_.clear();
    }

    for (std::shared_ptr<TimerState>& state : doomed) {
        if (state->phase == TimerPhase::Pending) {
            state->phase = TimerPhase::Cancelled;
            state->handle->ReleasePending();
        }
        state->ctx.reset();
    }
}

bool IocpService::EnsureConnectEx(SOCKET socketHint) {
    LPFN_CONNECTEX fn = g_connectEx.load(std::memory_order_acquire);
    if (fn) {
        return true;
    }

    SOCKET probe = socketHint;
    bool closeProbe = false;
    if (probe == INVALID_SOCKET) {
        probe = CreateTcpSocket(AF_INET);
        closeProbe = probe != INVALID_SOCKET;
    }
    if (probe == INVALID_SOCKET) {
        return false;
    }

    LPFN_CONNECTEX loaded = nullptr;
    const bool ok = LoadConnectEx(probe, &loaded);
    if (closeProbe) {
        closesocket(probe);
    }
    if (!ok || !loaded) {
        return false;
    }

    LPFN_CONNECTEX expected = nullptr;
    if (g_connectEx.compare_exchange_strong(expected, loaded, std::memory_order_release,
                                           std::memory_order_acquire)) {
        return true;
    }
    return g_connectEx.load(std::memory_order_acquire) != nullptr;
}

bool IocpService::Associate(SOCKET socket, const std::shared_ptr<IocpHandle>& handle) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || socket == INVALID_SOCKET || !handle) {
        return false;
    }
    return CreateIoCompletionPort(reinterpret_cast<HANDLE>(socket), iocp_,
                                  reinterpret_cast<ULONG_PTR>(handle.get()), 0) != nullptr;
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

bool IocpService::PostRecv(SOCKET socket, IoContext* ctx, const std::shared_ptr<IocpHandle>& handle,
                           size_t offset, size_t length) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || !handle ||
        socket == INVALID_SOCKET || !ValidRecvRange(ctx->buffer, offset, length)) {
        return false;
    }

    const size_t recvLen = length == 0 ? ctx->buffer.size() - offset : length;
    ctx->Reset(IoOp::Recv);
    BindContext(ctx, handle);
    ctx->socket = socket;
    ctx->wsaBuf.buf = ctx->buffer.data() + offset;
    ctx->wsaBuf.len = ToULong(recvLen);
    ctx->flags = 0;
    handle->AddPending();
    DWORD recvd = 0;
    const int r = WSARecv(socket, &ctx->wsaBuf, 1, &recvd, &ctx->flags, ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        ctx->handlePin.reset();
        return false;
    }
    return true;
}

bool IocpService::PostSend(SOCKET socket, IoContext* ctx, size_t offset, size_t length,
                           const std::shared_ptr<IocpHandle>& handle) {
    if (!ctx || !ValidBufferSendRange(ctx->buffer, offset, length)) {
        return false;
    }
    return PostSend(socket, ctx, ctx->buffer.data(), offset, length, handle);
}

bool IocpService::PostSend(SOCKET socket, IoContext* ctx, char* data, size_t offset, size_t length,
                           const std::shared_ptr<IocpHandle>& handle) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || !handle ||
        socket == INVALID_SOCKET || !data || !ValidExternalSendRange(offset, length)) {
        return false;
    }

    ctx->Reset(IoOp::Send);
    BindContext(ctx, handle);
    ctx->socket = socket;
    ctx->sendOffset = offset;
    ctx->sendLength = length;
    ctx->wsaBuf.buf = data + offset;
    ctx->wsaBuf.len = ToULong(length);
    handle->AddPending();
    DWORD sent = 0;
    const int r = WSASend(socket, &ctx->wsaBuf, 1, &sent, 0, ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        ctx->handlePin.reset();
        return false;
    }
    return true;
}

bool IocpService::PostRecvFrom(SOCKET socket, IoContext* ctx, const std::shared_ptr<IocpHandle>& handle) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || !handle ||
        socket == INVALID_SOCKET || ctx->buffer.empty() || !FitsULong(ctx->buffer.size())) {
        return false;
    }

    ctx->Reset(IoOp::RecvFrom);
    BindContext(ctx, handle);
    ctx->socket = socket;
    ctx->wsaBuf.buf = ctx->buffer.data();
    ctx->wsaBuf.len = ToULong(ctx->buffer.size());
    ctx->flags = 0;
    ctx->addrLen = sizeof(ctx->addr);
    handle->AddPending();
    DWORD recvd = 0;
    const int r = WSARecvFrom(socket, &ctx->wsaBuf, 1, &recvd, &ctx->flags,
                              reinterpret_cast<sockaddr*>(&ctx->addr), &ctx->addrLen,
                              ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        ctx->handlePin.reset();
        return false;
    }
    return true;
}

bool IocpService::PostSendTo(SOCKET socket, IoContext* ctx, size_t length,
                             const sockaddr* to, int toLen, const std::shared_ptr<IocpHandle>& handle) {
    if (!ctx || !ValidBufferSendRange(ctx->buffer, 0, length)) {
        return false;
    }
    return PostSendTo(socket, ctx, ctx->buffer.data(), length, to, toLen, handle);
}

bool IocpService::PostSendTo(SOCKET socket, IoContext* ctx, char* data, size_t length,
                             const sockaddr* to, int toLen, const std::shared_ptr<IocpHandle>& handle) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || !handle ||
        socket == INVALID_SOCKET || !data || !to || toLen <= 0 ||
        length == 0 || !FitsULong(length)) {
        return false;
    }

    ctx->Reset(IoOp::SendTo);
    BindContext(ctx, handle);
    ctx->socket = socket;
    ctx->wsaBuf.buf = data;
    ctx->wsaBuf.len = ToULong(length);
    handle->AddPending();
    DWORD sent = 0;
    const int r = WSASendTo(socket, &ctx->wsaBuf, 1, &sent, 0, to, toLen, ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        ctx->handlePin.reset();
        return false;
    }
    return true;
}

bool IocpService::PostConnect(SOCKET socket, IoContext* ctx, const sockaddr* name, int namelen,
                              const std::shared_ptr<IocpHandle>& handle) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || !handle ||
        socket == INVALID_SOCKET || !name || namelen <= 0 ||
        static_cast<size_t>(namelen) > sizeof(ctx->addr)) {
        return false;
    }
    if (!EnsureConnectEx(socket)) {
        return false;
    }

    const LPFN_CONNECTEX connectFn = g_connectEx.load(std::memory_order_acquire);
    if (!connectFn) {
        return false;
    }

    ctx->Reset(IoOp::Connect);
    BindContext(ctx, handle);
    ctx->socket = socket;
    std::memcpy(&ctx->addr, name, static_cast<size_t>(namelen));
    ctx->addrLen = namelen;
    handle->AddPending();
    DWORD bytesSent = 0;
    const BOOL ok = connectFn(socket, reinterpret_cast<const sockaddr*>(&ctx->addr),
                              ctx->addrLen, nullptr, 0, &bytesSent, ctx);
    if (!ok && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        ctx->handlePin.reset();
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
                             char* addrBuf, DWORD addrBufLen, const std::shared_ptr<IocpHandle>& handle,
                             LPFN_ACCEPTEX acceptEx) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || !handle || !acceptEx ||
        listenSocket == INVALID_SOCKET || acceptSocket == INVALID_SOCKET ||
        !ValidAcceptExAddrBuf(addrBuf, addrBufLen)) {
        return false;
    }

    ctx->Reset(IoOp::Accept);
    BindContext(ctx, handle);
    ctx->socket = acceptSocket;
    handle->AddPending();
    DWORD bytes = 0;
    const BOOL ok = acceptEx(listenSocket, acceptSocket, addrBuf, 0,
                             addrBufLen / 2, addrBufLen / 2,
                             &bytes, ctx);
    if (!ok && WSAGetLastError() != WSA_IO_PENDING) {
        handle->ReleasePending();
        ctx->handlePin.reset();
        return false;
    }
    return true;
}

bool IocpService::PostUser(const std::shared_ptr<IocpHandle>& handle, IoContext* ctx, uint64_t userKey) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !handle || !ctx) {
        return false;
    }

    ctx->Reset(IoOp::User);
    ctx->userKey = userKey;
    BindContext(ctx, handle);
    handle->AddPending();
    if (!PostIocpCompletion(iocp_, 0, reinterpret_cast<ULONG_PTR>(handle.get()), ctx)) {
        handle->ReleasePending();
        ctx->handlePin.reset();
        return false;
    }
    return true;
}

IocpService::TimerId IocpService::ScheduleTimeout(const std::shared_ptr<IocpHandle>& handle,
                                                    uint64_t userKey, int delayMs) {
    std::shared_lock lifecycle(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !handle || delayMs < 0) {
        return 0;
    }

    std::shared_ptr<TimerState> state = std::make_shared<TimerState>();
    state->ctx = std::make_unique<IoContext>(IoOp::User, 0);
    state->ctx->userKey = userKey;
    state->ctx->iocpOwned = true;
    state->handle = handle;
    state->id = nextTimerId_.fetch_add(1);
    if (state->id == 0) {
        state->id = nextTimerId_.fetch_add(1);
    }
    state->due = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
    state->phase = TimerPhase::Pending;

    handle->AddPending();

    {
        std::lock_guard lock(timerMutex_);
        timers_.emplace(state->id, state);
    }

    const HANDLE iocp = iocp_;
    if (!iocp || !PostIocpCompletion(iocp, 0, 0, nullptr)) {
        std::lock_guard lock(timerMutex_);
        const auto it = timers_.find(state->id);
        if (it != timers_.end() && it->second->phase == TimerPhase::Pending) {
            it->second->phase = TimerPhase::Cancelled;
            timers_.erase(it);
            handle->ReleasePending();
            return 0;
        }
        // Timer already claimed by AdvanceTimers(); completion is already scheduled.
    }

    return state->id;
}

void IocpService::CancelTimeout(TimerId id) {
    if (id == 0) {
        return;
    }

    std::shared_ptr<TimerState> state;
    {
        std::lock_guard lock(timerMutex_);
        const auto it = timers_.find(id);
        if (it == timers_.end()) {
            return;
        }
        state = it->second;
        if (state->phase != TimerPhase::Pending) {
            return;
        }
        state->phase = TimerPhase::Cancelled;
        timers_.erase(it);
    }

    state->handle->ReleasePending();
    state->ctx.reset();
}

DWORD IocpService::AdvanceTimers() {
    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    struct ClaimedTimer {
        std::shared_ptr<IocpHandle> handle;
        IoContext* ctx = nullptr;
    };
    std::vector<ClaimedTimer> claimed;
    DWORD waitMs = INFINITE;

    {
        std::lock_guard lock(timerMutex_);

        for (std::unordered_map<TimerId, std::shared_ptr<TimerState>>::iterator it = timers_.begin();
             it != timers_.end();) {
            if (it->second->due <= now) {
                std::shared_ptr<TimerState>& state = it->second;
                if (state->phase == TimerPhase::Pending) {
                    state->phase = TimerPhase::Claimed;
                    state->ctx->handlePin = state->handle;
                    claimed.push_back(ClaimedTimer{state->handle, state->ctx.release()});
                }
                it = timers_.erase(it);
            } else {
                ++it;
            }
        }

        if (!timers_.empty()) {
            std::chrono::steady_clock::time_point nearest = timers_.begin()->second->due;
            for (const auto& entry : timers_) {
                const std::chrono::steady_clock::time_point& dueTime = entry.second->due;
                if (dueTime < nearest) {
                    nearest = dueTime;
                }
            }
            if (nearest <= now) {
                waitMs = 0;
            } else {
                const auto ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(nearest - now).count();
                if (ms <= 0) {
                    waitMs = 0;
                } else if (ms >= static_cast<int64_t>(INFINITE - 1)) {
                    waitMs = INFINITE - 1;
                } else {
                    waitMs = static_cast<DWORD>(ms);
                }
            }
        }
    }

    if (!running_.load(std::memory_order_acquire)) {
        std::vector<IoContext*> orphaned;
        orphaned.reserve(claimed.size());
        for (ClaimedTimer& item : claimed) {
            orphaned.push_back(item.ctx);
        }
        CleanupClaimedContexts(orphaned);
        return 0;
    }

    {
        IocpLease iocpLease(*this);
        if (!iocpLease) {
            std::vector<IoContext*> orphaned;
            orphaned.reserve(claimed.size());
            for (ClaimedTimer& item : claimed) {
                orphaned.push_back(item.ctx);
            }
            CleanupClaimedContexts(orphaned);
            return waitMs;
        }

        for (ClaimedTimer& item : claimed) {
            if (!PostIocpCompletion(iocpLease.get(), 0,
                                    reinterpret_cast<ULONG_PTR>(item.handle.get()),
                                    item.ctx)) {
                if (item.ctx->handlePin) {
                    item.ctx->handlePin->ReleasePending();
                }
                if (item.ctx->iocpOwned) {
                    delete item.ctx;
                }
            }
        }
    }

    return waitMs;
}

void IocpService::WorkerLoop() {
    while (true) {
        const bool running = running_.load(std::memory_order_acquire);
        const DWORD waitMs = running ? AdvanceTimers() : 0;

        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* overlapped = nullptr;
        BOOL ok = FALSE;
        DWORD gqcsError = ERROR_SUCCESS;
        {
            IocpLease iocpLease(*this);
            if (!iocpLease) {
                break;
            }
            ok = GetQueuedCompletionStatus(iocpLease.get(), &bytes, &key, &overlapped, waitMs);
            if (!ok) {
                gqcsError = GetLastError();
            }
        }

        if (!ok && overlapped == nullptr) {
            if (gqcsError == WAIT_TIMEOUT) {
                if (!running_.load(std::memory_order_acquire)) {
                    break;
                }
                continue;
            }
            if (!running_.load(std::memory_order_acquire)) {
                break;
            }
            continue;
        }

        if (overlapped == nullptr && key == 0) {
            if (!running_.load(std::memory_order_acquire)) {
                break;
            }
            continue;
        }

        auto* ctx = static_cast<IoContext*>(overlapped);
        if (!ctx) {
            continue;
        }

        const bool iocpOwned = ctx->iocpOwned;
        std::shared_ptr<IocpHandle> pin = std::move(ctx->handlePin);
        if (!pin) {
            if (iocpOwned) {
                delete ctx;
            }
            continue;
        }

        {
            std::lock_guard completionLock(pin->completionMutex_);
            try {
                pin->OnIoCompleted(bytes, ok ? ERROR_SUCCESS : gqcsError, ctx);
            } catch (...) {
                // A completion target must not terminate the IOCP worker or skip accounting.
            }
        }

        if (iocpOwned) {
            delete ctx;
        }
        pin->ReleasePending();
    }
}
