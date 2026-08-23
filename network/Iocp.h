#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
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

    explicit IoContext(IoOp operation = IoOp::Recv, size_t bufSize = 0);
    void Reset(IoOp operation);
};

// Object associated with IOCP via completion key (raw this pointer).
// Lifetime must outlive all outstanding I/O (use shared_ptr + pending counter).
class IocpHandle : public std::enable_shared_from_this<IocpHandle> {
public:
    virtual ~IocpHandle() = default;
    virtual void OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) = 0;

    void AddPending() { ++pending_; }
    void ReleasePending() { --pending_; }
    int Pending() const { return pending_.load(); }
    /// Wait until outstanding IOCP ops complete (after cancel/close).
    bool WaitPendingZero(int timeoutMs = 5000) const;

private:
    std::atomic<int> pending_{0};
};

class IocpService {
public:
    using TimerId = uint64_t;

    explicit IocpService(unsigned workerCount = 0);
    ~IocpService();

    IocpService(const IocpService&) = delete;
    IocpService& operator=(const IocpService&) = delete;

    bool Start();
    void Stop();

    bool Associate(SOCKET socket, IocpHandle* handle);

    bool PostRecv(SOCKET socket, IoContext* ctx, IocpHandle* handle);
    bool PostSend(SOCKET socket, IoContext* ctx, size_t offset, size_t length, IocpHandle* handle);
    /// Send from caller-owned buffer (must stay valid until completion).
    bool PostSend(SOCKET socket, IoContext* ctx, char* data, size_t offset, size_t length,
                  IocpHandle* handle);
    bool PostRecvFrom(SOCKET socket, IoContext* ctx, IocpHandle* handle);
    bool PostSendTo(SOCKET socket, IoContext* ctx, size_t length,
                    const sockaddr* to, int toLen, IocpHandle* handle);
    /// SendTo from caller-owned buffer (must stay valid until completion).
    bool PostSendTo(SOCKET socket, IoContext* ctx, char* data, size_t length,
                    const sockaddr* to, int toLen, IocpHandle* handle);
    bool PostConnect(SOCKET socket, IoContext* ctx, const sockaddr* name, int namelen, IocpHandle* handle);
    bool PostAccept(SOCKET listenSocket, SOCKET acceptSocket, IoContext* ctx,
                    char* addrBuf, DWORD addrBufLen, IocpHandle* handle, LPFN_ACCEPTEX acceptEx);
    bool PostUser(IocpHandle* handle, IoContext* ctx, uint64_t userKey = 0);

    /// Schedule a User completion after delayMs (driven by GQCS wait, no threadpool).
    TimerId ScheduleTimeout(IocpHandle* handle, uint64_t userKey, int delayMs);
    void CancelTimeout(TimerId id);

    static SOCKET CreateTcpSocket(int family);
    static SOCKET CreateUdpSocket(int family);
    static bool BindAny(SOCKET socket, int family);
    static bool LoadConnectEx(SOCKET socket, LPFN_CONNECTEX* outFn);
    static bool LoadAcceptEx(SOCKET socket, LPFN_ACCEPTEX* outFn);

    bool IsRunning() const { return running_.load(); }

private:
    struct TimerEntry {
        TimerId id = 0;
        std::chrono::steady_clock::time_point due{};
        IocpHandle* handle = nullptr;
        IoContext* ctx = nullptr;
    };

    void WorkerLoop();
    DWORD AdvanceTimers();
    void ClearTimers();

    static LPFN_CONNECTEX connectEx_;
    static std::once_flag connectExInit_;

    HANDLE iocp_ = nullptr;
    std::atomic<bool> running_{false};
    unsigned workerCount_ = 4;
    std::vector<std::thread> workers_;

    std::mutex timerMutex_;
    std::unordered_map<TimerId, TimerEntry> timers_;
    std::atomic<TimerId> nextTimerId_{1};
};
