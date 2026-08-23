#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <MSWSock.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <vector>

enum class IoOp : uint8_t {
    Recv = 1,
    Send,
    Connect,
    RecvFrom,
    SendTo,
    Accept,
    User
};
struct IoContext;

// IOCP completion target. Must be owned by std::shared_ptr while I/O is outstanding.
class IocpHandle : public std::enable_shared_from_this<IocpHandle> {
public:
    virtual ~IocpHandle() = default;
    virtual void OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) = 0;

    void AddPending();
    void ReleasePending();
    int Pending() const { return pending_.load(std::memory_order_acquire); }
    /// Wait until outstanding IOCP ops complete (after cancel/close).
    bool WaitPendingZero(int timeoutMs = 5000) const;

protected:
    // IOCP may dispatch different contexts for one handle on different workers.
    // Recursive because completion handlers can call Close()/Stop().
    mutable std::recursive_mutex completionMutex_;

private:
    friend class IocpService;
    std::atomic<int> pending_{0};
    mutable std::mutex pendingMutex_;
    mutable std::condition_variable pendingCv_;
};

struct IoContext : OVERLAPPED {
    IoOp op = IoOp::Recv;
    SOCKET socket = INVALID_SOCKET;
    WSABUF wsaBuf{};
    std::vector<char> buffer;
    sockaddr_storage addr{};
    int addrLen = 0;
    DWORD flags = 0;
    size_t sendOffset = 0;
    size_t sendLength = 0;
    uint64_t userKey = 0;
    /// Set for heap IoContext objects allocated by ScheduleTimeout.
    bool iocpOwned = false;
    /// Pins IocpHandle lifetime until this I/O completes.
    std::shared_ptr<IocpHandle> handlePin;
    /// Independent accounting pin used to recover completion bookkeeping.
    std::shared_ptr<IocpHandle> accountingPin;
    /// Owns a snapshot used by PostSend/PostSendTo external-buffer overloads.
    std::shared_ptr<std::vector<char>> bufferPin;
    /// Socket/HANDLE on which the overlapped operation was issued.
    SOCKET cancellationSocket = INVALID_SOCKET;

    explicit IoContext(IoOp operation = IoOp::Recv, size_t bufSize = 0);
    void Reset(IoOp operation);
};

class IocpService {
public:
    using TimerId = uint64_t;

    explicit IocpService(unsigned workerCount = 0);
    ~IocpService();

    IocpService(const IocpService&) = delete;
    IocpService& operator=(const IocpService&) = delete;

    bool Start();
    /// Cancels registered socket I/O, then blocks until every posted operation completes.
    /// Socket ownership remains with the caller; Stop() never closes sockets.
    /// Must not be called from an OnIoCompleted callback.
    void Stop();

    bool Associate(SOCKET socket, const std::shared_ptr<IocpHandle>& handle);

    bool PostRecv(SOCKET socket, IoContext* ctx, const std::shared_ptr<IocpHandle>& handle,
                  size_t offset = 0, size_t length = 0);
    bool PostSend(SOCKET socket, IoContext* ctx, size_t offset, size_t length,
                  const std::shared_ptr<IocpHandle>& handle);
    /// Takes an internal snapshot of the requested caller buffer range.
    bool PostSend(SOCKET socket, IoContext* ctx, char* data, size_t offset, size_t length,
                  const std::shared_ptr<IocpHandle>& handle);
    bool PostRecvFrom(SOCKET socket, IoContext* ctx, const std::shared_ptr<IocpHandle>& handle);
    bool PostSendTo(SOCKET socket, IoContext* ctx, size_t length,
                    const sockaddr* to, int toLen, const std::shared_ptr<IocpHandle>& handle);
    /// Takes an internal snapshot of the caller buffer.
    bool PostSendTo(SOCKET socket, IoContext* ctx, char* data, size_t length,
                    const sockaddr* to, int toLen, const std::shared_ptr<IocpHandle>& handle);
    bool PostConnect(SOCKET socket, IoContext* ctx, const sockaddr* name, int namelen,
                     const std::shared_ptr<IocpHandle>& handle);
    /// addrBuf must refer to ctx->buffer, which owns the storage until completion.
    bool PostAccept(SOCKET listenSocket, SOCKET acceptSocket, IoContext* ctx,
                    char* addrBuf, DWORD addrBufLen, const std::shared_ptr<IocpHandle>& handle,
                    LPFN_ACCEPTEX acceptEx);
    bool PostUser(const std::shared_ptr<IocpHandle>& handle, IoContext* ctx, uint64_t userKey = 0);

    /// Schedule a User completion after delayMs (driven by GQCS wait, no threadpool).
    TimerId ScheduleTimeout(const std::shared_ptr<IocpHandle>& handle, uint64_t userKey, int delayMs);
    void CancelTimeout(TimerId id);

    static SOCKET CreateTcpSocket(int family);
    static SOCKET CreateUdpSocket(int family);
    static bool BindAny(SOCKET socket, int family);
    static bool LoadConnectEx(SOCKET socket, LPFN_CONNECTEX* outFn);
    static bool LoadAcceptEx(SOCKET socket, LPFN_ACCEPTEX* outFn);

    bool IsRunning() const { return running_.load(std::memory_order_acquire); }

private:
    enum class TimerPhase : uint8_t { Publishing, Pending, Claimed, Cancelled };

    struct TimerState {
        TimerId id = 0;
        std::chrono::steady_clock::time_point due{};
        std::shared_ptr<IocpHandle> handle;
        std::unique_ptr<IoContext> ctx;
        TimerPhase phase = TimerPhase::Pending;
    };

    void WorkerLoop();
    DWORD AdvanceTimers();
    void ClearTimers();
    void CancelOutstandingSocketIo();
    void WakeWorkers(HANDLE iocp, size_t count);

    /// RAII: pins IOCP handle for worker IO until destroyed.
    class IocpLease {
    public:
        explicit IocpLease(IocpService& svc);
        ~IocpLease();
        IocpLease(const IocpLease&) = delete;
        IocpLease& operator=(const IocpLease&) = delete;
        explicit operator bool() const { return handle_ != nullptr; }
        HANDLE get() const { return handle_; }

    private:
        IocpService& svc_;
        HANDLE handle_{nullptr};
    };

    void WaitIocpIdle() const;

    void PinIocpHandle();
    void UnpinIocpHandle();
    void AddOutstanding(IoContext& ctx, const std::shared_ptr<IocpHandle>& handle,
                        SOCKET cancellationSocket = INVALID_SOCKET);
    void UnregisterPendingSocket(SOCKET cancellationSocket);
    void ReleaseOutstanding(IocpHandle& handle, SOCKET cancellationSocket);
    void ReleaseOutstandingWithoutHandle(SOCKET cancellationSocket);
    void WaitOutstandingZero() const;
    bool PostIocpCompletion(HANDLE iocp, DWORD bytes, ULONG_PTR key, OVERLAPPED* overlapped);

    HANDLE iocp_ = nullptr;
    std::atomic<int> iocpUsers_{0};
    std::atomic<int> outstandingIo_{0};
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    mutable std::mutex iocpIdleMutex_;
    mutable std::condition_variable iocpIdleCv_;
    mutable std::mutex outstandingMutex_;
    mutable std::condition_variable outstandingCv_;
    std::mutex pendingSocketMutex_;
    std::unordered_map<SOCKET, size_t> pendingSockets_;
    std::mutex transitionMutex_;
    unsigned workerCount_ = 4;
    std::vector<std::thread> workers_;

    std::shared_mutex lifecycleMutex_;
    std::mutex timerMutex_;
    std::unordered_map<TimerId, std::shared_ptr<TimerState>> timers_;
    std::atomic<TimerId> nextTimerId_{1};
};
