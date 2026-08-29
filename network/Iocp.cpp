#include "Iocp.h"

#include <climits>
#include <cstring>
#include <exception>
#include <limits>
#include <utility>

namespace {

thread_local IocpService* g_currentIocpWorker = nullptr;

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

void ClearContextPins(IoContext* ctx) {
    ctx->handlePin.reset();
    ctx->accountingPin.reset();
    ctx->cancellationSocket = INVALID_SOCKET;
}

bool IsBoundForConnectEx(SOCKET socket, int family) {
    sockaddr_storage local{};
    int localLen = sizeof(local);
    return getsockname(socket, reinterpret_cast<sockaddr*>(&local), &localLen) == 0 &&
           local.ss_family == family;
}

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
    if (handlePin || accountingPin) {
        OutputDebugStringA("Attempted to reset an outstanding IoContext\n");
        return;
    }
    std::memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED));
    op = operation;
    flags = 0;
    sendOffset = 0;
    sendLength = 0;
    userKey = 0;
    bufferPin.reset();
    cancellationSocket = INVALID_SOCKET;
    addrLen = sizeof(addr);
}

void IocpHandle::AddPending() {
    pending_.fetch_add(1, std::memory_order_acq_rel);
}

void IocpHandle::ReleasePending() {
    int previous = pending_.load(std::memory_order_acquire);
    while (previous > 0 &&
           !pending_.compare_exchange_weak(previous, previous - 1,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
    }
    if (previous <= 0) {
        OutputDebugStringA("IocpHandle pending counter underflow\n");
        return;
    }
    if (previous == 1) {
        std::lock_guard lock(pendingMutex_);
        pendingCv_.notify_all();
    }
}

bool IocpHandle::WaitPendingZero(int timeoutMs) const {
    std::unique_lock lock(pendingMutex_);
    const auto idle = [this] {
        return pending_.load(std::memory_order_acquire) == 0;
    };
    if (timeoutMs < 0) {
        pendingCv_.wait(lock, idle);
        return true;
    }
    return pendingCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), idle);
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
    std::lock_guard transition(transitionMutex_);
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
        WakeWorkers(iocp_, workers_.size());

        lock.unlock();
        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        lock.lock();

        workers_.clear();
        WaitIocpIdle();
        CloseHandle(iocp_);
        iocp_ = nullptr;
        stopping_.store(false, std::memory_order_release);
        return false;
    }

    return true;
}

void IocpService::Stop() {
    if (g_currentIocpWorker == this) {
        OutputDebugStringA("IocpService::Stop cannot run from its completion worker\n");
        return;
    }
    std::lock_guard transition(transitionMutex_);
    HANDLE iocpToClose = nullptr;
    size_t workerCount = 0;

    {
        std::unique_lock lock(lifecycleMutex_);
        if (!running_.exchange(false, std::memory_order_acq_rel)) {
            return;
        }
        stopping_.store(true, std::memory_order_release);

        ClearTimers();

        iocpToClose = iocp_;
        workerCount = workers_.size();
        CancelOutstandingSocketIo();
        WakeWorkers(iocpToClose, workerCount);
    }

    WaitOutstandingZero();

    {
        std::shared_lock lock(lifecycleMutex_);
        if (iocp_ == iocpToClose && iocpToClose) {
            WakeWorkers(iocpToClose, workerCount);
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
    int previous = iocpUsers_.load(std::memory_order_acquire);
    while (previous > 0 &&
           !iocpUsers_.compare_exchange_weak(previous, previous - 1,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire)) {
    }
    if (previous <= 0) {
        OutputDebugStringA("IocpService IOCP user counter underflow\n");
        std::lock_guard lock(iocpIdleMutex_);
        iocpIdleCv_.notify_all();
        return;
    }
    if (previous == 1) {
        std::lock_guard lock(iocpIdleMutex_);
        iocpIdleCv_.notify_all();
    }
}

void IocpService::AddOutstanding(IoContext& ctx,
                                 const std::shared_ptr<IocpHandle>& handle,
                                 SOCKET cancellationSocket) {
    if (cancellationSocket != INVALID_SOCKET) {
        std::lock_guard lock(pendingSocketMutex_);
        ++pendingSockets_[cancellationSocket];
    }
    ctx.handlePin = handle;
    ctx.accountingPin = handle;
    ctx.cancellationSocket = cancellationSocket;
    handle->AddPending();
    outstandingIo_.fetch_add(1, std::memory_order_acq_rel);
}

void IocpService::UnregisterPendingSocket(SOCKET cancellationSocket) {
    if (cancellationSocket != INVALID_SOCKET) {
        std::lock_guard lock(pendingSocketMutex_);
        const auto it = pendingSockets_.find(cancellationSocket);
        if (it == pendingSockets_.end() || it->second == 0) {
            OutputDebugStringA("Missing pending socket accounting entry\n");
        } else if (--it->second == 0) {
            pendingSockets_.erase(it);
        }
    }
}

void IocpService::ReleaseOutstanding(IocpHandle& handle, SOCKET cancellationSocket) {
    UnregisterPendingSocket(cancellationSocket);
    handle.ReleasePending();
    ReleaseOutstandingWithoutHandle(INVALID_SOCKET);
}

void IocpService::ReleaseOutstandingWithoutHandle(SOCKET cancellationSocket) {
    UnregisterPendingSocket(cancellationSocket);
    int previous = outstandingIo_.load(std::memory_order_acquire);
    while (previous > 0 &&
           !outstandingIo_.compare_exchange_weak(previous, previous - 1,
                                                 std::memory_order_acq_rel,
                                                 std::memory_order_acquire)) {
    }
    if (previous <= 0) {
        OutputDebugStringA("IocpService outstanding I/O counter underflow\n");
        return;
    }
    if (previous == 1) {
        std::lock_guard lock(outstandingMutex_);
        outstandingCv_.notify_all();
    }
}

void IocpService::WaitOutstandingZero() const {
    std::unique_lock lock(outstandingMutex_);
    outstandingCv_.wait(lock, [this] {
        return outstandingIo_.load(std::memory_order_acquire) == 0;
    });
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
        if (state->phase == TimerPhase::Pending ||
            state->phase == TimerPhase::Publishing) {
            state->phase = TimerPhase::Cancelled;
            ReleaseOutstanding(*state->handle, INVALID_SOCKET);
        }
        state->ctx.reset();
    }
}

void IocpService::CancelOutstandingSocketIo() {
    std::lock_guard lock(pendingSocketMutex_);
    for (const auto& [socket, count] : pendingSockets_) {
        if (count == 0) {
            continue;
        }
        if (!CancelIoEx(reinterpret_cast<HANDLE>(socket), nullptr)) {
            const DWORD error = GetLastError();
            if (error != ERROR_NOT_FOUND && error != ERROR_INVALID_HANDLE) {
                std::string message = "CancelIoEx failed during IOCP shutdown: ";
                message += std::to_string(error);
                message += '\n';
                OutputDebugStringA(message.c_str());
            }
        }
    }
}

void IocpService::WakeWorkers(HANDLE iocp, size_t count) {
    if (!iocp) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        PostIocpCompletion(iocp, 0, 0, nullptr);
    }
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
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || ctx->iocpOwned ||
        (ctx->handlePin || ctx->accountingPin) || !handle ||
        socket == INVALID_SOCKET || !ValidRecvRange(ctx->buffer, offset, length)) {
        return false;
    }

    const size_t recvLen = length == 0 ? ctx->buffer.size() - offset : length;
    ctx->Reset(IoOp::Recv);
    ctx->socket = socket;
    ctx->wsaBuf.buf = ctx->buffer.data() + offset;
    ctx->wsaBuf.len = ToULong(recvLen);
    ctx->flags = 0;
    AddOutstanding(*ctx, handle, socket);
    DWORD recvd = 0;
    const int r = WSARecv(socket, &ctx->wsaBuf, 1, &recvd, &ctx->flags, ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        ReleaseOutstanding(*handle, ctx->cancellationSocket);
        ClearContextPins(ctx);
        ctx->bufferPin.reset();
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
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || ctx->iocpOwned ||
        (ctx->handlePin || ctx->accountingPin) || !handle ||
        socket == INVALID_SOCKET || !data || !ValidExternalSendRange(offset, length)) {
        return false;
    }

    auto bufferPin = std::make_shared<std::vector<char>>(data + offset, data + offset + length);
    ctx->Reset(IoOp::Send);
    ctx->bufferPin = std::move(bufferPin);
    ctx->socket = socket;
    ctx->sendOffset = offset;
    ctx->sendLength = length;
    ctx->wsaBuf.buf = ctx->bufferPin->data();
    ctx->wsaBuf.len = ToULong(length);
    AddOutstanding(*ctx, handle, socket);
    DWORD sent = 0;
    const int r = WSASend(socket, &ctx->wsaBuf, 1, &sent, 0, ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        ReleaseOutstanding(*handle, ctx->cancellationSocket);
        ClearContextPins(ctx);
        ctx->bufferPin.reset();
        return false;
    }
    return true;
}

bool IocpService::PostRecvFrom(SOCKET socket, IoContext* ctx, const std::shared_ptr<IocpHandle>& handle) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || ctx->iocpOwned ||
        (ctx->handlePin || ctx->accountingPin) || !handle ||
        socket == INVALID_SOCKET || ctx->buffer.empty() || !FitsULong(ctx->buffer.size())) {
        return false;
    }

    ctx->Reset(IoOp::RecvFrom);
    ctx->socket = socket;
    ctx->wsaBuf.buf = ctx->buffer.data();
    ctx->wsaBuf.len = ToULong(ctx->buffer.size());
    ctx->flags = 0;
    ctx->addrLen = sizeof(ctx->addr);
    AddOutstanding(*ctx, handle, socket);
    DWORD recvd = 0;
    const int r = WSARecvFrom(socket, &ctx->wsaBuf, 1, &recvd, &ctx->flags,
                              reinterpret_cast<sockaddr*>(&ctx->addr), &ctx->addrLen,
                              ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        ReleaseOutstanding(*handle, ctx->cancellationSocket);
        ClearContextPins(ctx);
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
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || ctx->iocpOwned ||
        (ctx->handlePin || ctx->accountingPin) || !handle ||
        socket == INVALID_SOCKET || !data || !to || toLen <= 0 ||
        static_cast<size_t>(toLen) > sizeof(ctx->addr) ||
        length == 0 || !FitsULong(length)) {
        return false;
    }

    auto bufferPin = std::make_shared<std::vector<char>>(data, data + length);
    ctx->Reset(IoOp::SendTo);
    ctx->bufferPin = std::move(bufferPin);
    ctx->socket = socket;
    ctx->wsaBuf.buf = ctx->bufferPin->data();
    ctx->wsaBuf.len = ToULong(length);
    std::memcpy(&ctx->addr, to, static_cast<size_t>(toLen));
    ctx->addrLen = toLen;
    AddOutstanding(*ctx, handle, socket);
    DWORD sent = 0;
    const int r = WSASendTo(socket, &ctx->wsaBuf, 1, &sent, 0,
                            reinterpret_cast<const sockaddr*>(&ctx->addr), ctx->addrLen,
                            ctx, nullptr);
    if (r == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        ReleaseOutstanding(*handle, ctx->cancellationSocket);
        ClearContextPins(ctx);
        ctx->bufferPin.reset();
        return false;
    }
    return true;
}

bool IocpService::PostConnect(SOCKET socket, IoContext* ctx, const sockaddr* name, int namelen,
                              const std::shared_ptr<IocpHandle>& handle) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || ctx->iocpOwned ||
        (ctx->handlePin || ctx->accountingPin) || !handle ||
        socket == INVALID_SOCKET || !name || namelen <= 0 ||
        static_cast<size_t>(namelen) > sizeof(ctx->addr)) {
        return false;
    }
    const int family = name->sa_family;
    if ((family != AF_INET && family != AF_INET6) ||
        !IsBoundForConnectEx(socket, family)) {
        return false;
    }

    LPFN_CONNECTEX connectFn = nullptr;
    if (!LoadConnectEx(socket, &connectFn) || !connectFn) {
        return false;
    }

    ctx->Reset(IoOp::Connect);
    ctx->socket = socket;
    std::memcpy(&ctx->addr, name, static_cast<size_t>(namelen));
    ctx->addrLen = namelen;
    AddOutstanding(*ctx, handle, socket);
    DWORD bytesSent = 0;
    const BOOL ok = connectFn(socket, reinterpret_cast<const sockaddr*>(&ctx->addr),
                              ctx->addrLen, nullptr, 0, &bytesSent, ctx);
    if (!ok && WSAGetLastError() != WSA_IO_PENDING) {
        ReleaseOutstanding(*handle, ctx->cancellationSocket);
        ClearContextPins(ctx);
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
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !ctx || ctx->iocpOwned ||
        (ctx->handlePin || ctx->accountingPin) ||
        !handle || !acceptEx ||
        listenSocket == INVALID_SOCKET || acceptSocket == INVALID_SOCKET ||
        ctx->buffer.data() != addrBuf || ctx->buffer.size() < addrBufLen ||
        !ValidAcceptExAddrBuf(addrBuf, addrBufLen)) {
        return false;
    }

    ctx->Reset(IoOp::Accept);
    ctx->socket = acceptSocket;
    AddOutstanding(*ctx, handle, listenSocket);
    DWORD bytes = 0;
    const BOOL ok = acceptEx(listenSocket, acceptSocket, addrBuf, 0,
                             addrBufLen / 2, addrBufLen / 2,
                             &bytes, ctx);
    if (!ok && WSAGetLastError() != WSA_IO_PENDING) {
        ReleaseOutstanding(*handle, ctx->cancellationSocket);
        ClearContextPins(ctx);
        return false;
    }
    return true;
}

bool IocpService::PostUser(const std::shared_ptr<IocpHandle>& handle, IoContext* ctx, uint64_t userKey) {
    std::shared_lock lock(lifecycleMutex_);
    if (!running_.load(std::memory_order_acquire) || !iocp_ || !handle || !ctx ||
        ctx->iocpOwned || ctx->handlePin || ctx->accountingPin) {
        return false;
    }

    ctx->Reset(IoOp::User);
    ctx->userKey = userKey;
    AddOutstanding(*ctx, handle);
    if (!PostIocpCompletion(iocp_, 0, reinterpret_cast<ULONG_PTR>(handle.get()), ctx)) {
        ReleaseOutstanding(*handle, ctx->cancellationSocket);
        ClearContextPins(ctx);
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
    state->due = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
    state->phase = TimerPhase::Publishing;

    AddOutstanding(*state->ctx, handle);
    try {
        std::lock_guard lock(timerMutex_);
        do {
            state->id = nextTimerId_.fetch_add(1, std::memory_order_relaxed);
        } while (state->id == 0 || timers_.contains(state->id));

        timers_.emplace(state->id, state);
    } catch (...) {
        ReleaseOutstanding(*handle, INVALID_SOCKET);
        ClearContextPins(state->ctx.get());
        return 0;
    }

    const bool scheduled = PostIocpCompletion(iocp_, 0, 0, nullptr);
    {
        std::lock_guard lock(timerMutex_);
        if (!scheduled) {
            state->phase = TimerPhase::Cancelled;
            timers_.erase(state->id);
        } else {
            state->phase = TimerPhase::Pending;
        }
    }
    if (!scheduled) {
        OutputDebugStringA("Failed to wake IOCP worker for a scheduled timer\n");
        ReleaseOutstanding(*handle, INVALID_SOCKET);
        return 0;
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

    ReleaseOutstanding(*state->handle, INVALID_SOCKET);
    state->ctx.reset();

    IocpLease iocpLease(*this);
    if (iocpLease) {
        PostIocpCompletion(iocpLease.get(), 0, 0, nullptr);
    }
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
            if (it->second->due <= now &&
                it->second->phase == TimerPhase::Pending) {
                std::shared_ptr<TimerState>& state = it->second;
                state->phase = TimerPhase::Claimed;
                state->ctx->handlePin = state->handle;
                claimed.push_back(ClaimedTimer{state->handle, state->ctx.release()});
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

    const auto discardClaimed = [this](ClaimedTimer& item) {
        if (!item.ctx) {
            return;
        }
        std::shared_ptr<IocpHandle> accounting =
            item.ctx->handlePin ? item.ctx->handlePin : item.ctx->accountingPin;
        if (accounting) {
            ReleaseOutstanding(*accounting, item.ctx->cancellationSocket);
        } else {
            ReleaseOutstandingWithoutHandle(item.ctx->cancellationSocket);
        }
        if (item.ctx->iocpOwned) {
            delete item.ctx;
        }
        item.ctx = nullptr;
    };

    if (!running_.load(std::memory_order_acquire)) {
        for (ClaimedTimer& item : claimed) {
            discardClaimed(item);
        }
        return 0;
    }

    {
        IocpLease iocpLease(*this);
        if (!iocpLease) {
            for (ClaimedTimer& item : claimed) {
                discardClaimed(item);
            }
            return waitMs;
        }

        for (ClaimedTimer& item : claimed) {
            if (!PostIocpCompletion(iocpLease.get(), 0,
                                    reinterpret_cast<ULONG_PTR>(item.handle.get()),
                                    item.ctx)) {
                discardClaimed(item);
            }
        }
    }

    return waitMs;
}

void IocpService::WorkerLoop() {
    IocpService* previousWorkerService = g_currentIocpWorker;
    g_currentIocpWorker = this;
    while (true) {
        const bool running = running_.load(std::memory_order_acquire);
        const bool shutdownComplete =
            !running && outstandingIo_.load(std::memory_order_acquire) == 0;
        const DWORD waitMs = running ? AdvanceTimers() : (shutdownComplete ? 0 : INFINITE);

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
                if (!running_.load(std::memory_order_acquire) &&
                    outstandingIo_.load(std::memory_order_acquire) == 0) {
                    break;
                }
                continue;
            }
            if (!running_.load(std::memory_order_acquire) &&
                outstandingIo_.load(std::memory_order_acquire) == 0) {
                break;
            }
            std::string message = "GetQueuedCompletionStatus failed without OVERLAPPED: ";
            message += std::to_string(gqcsError);
            message += '\n';
            OutputDebugStringA(message.c_str());
            break;
        }

        if (overlapped == nullptr && key == 0) {
            if (!running_.load(std::memory_order_acquire) &&
                outstandingIo_.load(std::memory_order_acquire) == 0) {
                break;
            }
            continue;
        }

        auto* ctx = static_cast<IoContext*>(overlapped);
        if (!ctx) {
            continue;
        }

        const bool iocpOwned = ctx->iocpOwned;
        const SOCKET cancellationSocket = ctx->cancellationSocket;
        std::shared_ptr<IocpHandle> pin = std::move(ctx->handlePin);
        std::shared_ptr<IocpHandle> accountingPin = std::move(ctx->accountingPin);
        UnregisterPendingSocket(cancellationSocket);
        if (!pin) {
            pin = std::move(accountingPin);
        } else {
            accountingPin.reset();
        }
        if (!pin) {
            OutputDebugStringA("IOCP completion arrived without either lifetime pin\n");
            ReleaseOutstandingWithoutHandle(INVALID_SOCKET);
            if (iocpOwned) {
                delete ctx;
            }
            continue;
        }

        DWORD completionError = ok ? ERROR_SUCCESS : gqcsError;
        {
            std::lock_guard completionLock(pin->completionMutex_);
            if (completionError == ERROR_SUCCESS && ctx->op == IoOp::Connect) {
                if (setsockopt(ctx->socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT,
                               nullptr, 0) != 0) {
                    completionError = static_cast<DWORD>(WSAGetLastError());
                }
            } else if (completionError == ERROR_SUCCESS && ctx->op == IoOp::Accept) {
                if (setsockopt(ctx->socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                               reinterpret_cast<const char*>(&cancellationSocket),
                               sizeof(cancellationSocket)) != 0) {
                    completionError = static_cast<DWORD>(WSAGetLastError());
                }
            }
            try {
                pin->OnIoCompleted(bytes, completionError, ctx);
            } catch (const std::exception& ex) {
                std::string message = "Exception escaped OnIoCompleted: ";
                message += ex.what();
                message += '\n';
                OutputDebugStringA(message.c_str());
            } catch (...) {
                OutputDebugStringA("Unknown exception escaped OnIoCompleted\n");
            }
        }

        if (iocpOwned) {
            delete ctx;
        }
        ReleaseOutstanding(*pin, INVALID_SOCKET);
    }
    g_currentIocpWorker = previousWorkerService;
}
