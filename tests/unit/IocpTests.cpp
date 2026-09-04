#include "../TestFramework.h"

#include "../../network/Iocp.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace {

class RecordingHandle : public IocpHandle {
public:
    void OnIoCompleted(DWORD bytes, DWORD error, IoContext* ctx) override {
        std::lock_guard lock(mutex_);
        ++completions_;
        lastBytes_ = bytes;
        lastError_ = error;
        if (ctx) {
            lastOp_ = ctx->op;
            lastUserKey_ = ctx->userKey;
            if (ctx->op == IoOp::Recv && bytes > 0 && !ctx->buffer.empty()) {
                lastPayload_.assign(ctx->buffer.data(),
                                    ctx->buffer.data() + bytes);
            }
        }
        cv_.notify_all();
    }

    bool WaitCompletions(int expected, int timeoutMs = 3000) {
        std::unique_lock lock(mutex_);
        return cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&] {
            return completions_ >= expected;
        });
    }

    int Completions() const {
        std::lock_guard lock(mutex_);
        return completions_;
    }

    IoOp LastOp() const {
        std::lock_guard lock(mutex_);
        return lastOp_;
    }

    uint64_t LastUserKey() const {
        std::lock_guard lock(mutex_);
        return lastUserKey_;
    }

    std::string LastPayload() const {
        std::lock_guard lock(mutex_);
        return lastPayload_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    int completions_ = 0;
    DWORD lastBytes_ = 0;
    DWORD lastError_ = 0;
    IoOp lastOp_ = IoOp::Recv;
    uint64_t lastUserKey_ = 0;
    std::string lastPayload_;
};

SOCKET BindLoopbackTcp(uint16_t& portOut) {
    SOCKET s = IocpService::CreateTcpSocket(AF_INET);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    int len = sizeof(addr);
    getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    portOut = ntohs(addr.sin_port);
    return s;
}

}  // namespace

TEST(Iocp, StartStopIsIdempotentSafe) {
    IocpService iocp(2);
    EXPECT_TRUE(iocp.Start());
    EXPECT_TRUE(iocp.IsRunning());
    iocp.Stop();
    EXPECT_FALSE(iocp.IsRunning());
    iocp.Stop();
}

TEST(Iocp, ScheduleTimeoutFiresUserCompletion) {
    IocpService iocp(2);
    EXPECT_TRUE(iocp.Start());
    auto handle = std::make_shared<RecordingHandle>();
    const auto id = iocp.ScheduleTimeout(handle, 42, 40);
    EXPECT_TRUE(id != 0);
    EXPECT_TRUE(handle->WaitCompletions(1, 2000));
    EXPECT_EQ(static_cast<int>(handle->LastOp()), static_cast<int>(IoOp::User));
    EXPECT_EQ(handle->LastUserKey(), 42ull);
    iocp.Stop();
}

TEST(Iocp, CancelTimeoutPreventsCompletion) {
    IocpService iocp(2);
    EXPECT_TRUE(iocp.Start());
    auto handle = std::make_shared<RecordingHandle>();
    const auto id = iocp.ScheduleTimeout(handle, 7, 400);
    EXPECT_TRUE(id != 0);
    iocp.CancelTimeout(id);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(handle->Completions(), 0);
    iocp.Stop();
}

TEST(Iocp, PostUserDeliversImmediately) {
    IocpService iocp(2);
    EXPECT_TRUE(iocp.Start());
    auto handle = std::make_shared<RecordingHandle>();
    IoContext ctx{IoOp::User, 0};
    EXPECT_TRUE(iocp.PostUser(handle, &ctx, 99));
    EXPECT_TRUE(handle->WaitCompletions(1));
    EXPECT_EQ(static_cast<int>(handle->LastOp()), static_cast<int>(IoOp::User));
    EXPECT_EQ(handle->LastUserKey(), 99ull);
    EXPECT_TRUE(handle->WaitPendingZero());
    iocp.Stop();
}

TEST(Iocp, TcpRecvSendOnLoopback) {
    IocpService iocp(2);
    EXPECT_TRUE(iocp.Start());

    uint16_t port = 0;
    SOCKET listenSock = BindLoopbackTcp(port);
    EXPECT_TRUE(listenSock != INVALID_SOCKET);
    EXPECT_TRUE(listen(listenSock, 1) == 0);

    SOCKET client = IocpService::CreateTcpSocket(AF_INET);
    EXPECT_TRUE(client != INVALID_SOCKET);
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    EXPECT_TRUE(connect(client, reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) == 0);

    SOCKET accepted = accept(listenSock, nullptr, nullptr);
    EXPECT_TRUE(accepted != INVALID_SOCKET);

    auto recvHandle = std::make_shared<RecordingHandle>();
    EXPECT_TRUE(iocp.Associate(accepted, recvHandle));
    IoContext recvCtx{IoOp::Recv, 256};
    EXPECT_TRUE(iocp.PostRecv(accepted, &recvCtx, recvHandle));

    const char msg[] = "iocp-ping";
    EXPECT_TRUE(send(client, msg, static_cast<int>(sizeof(msg) - 1), 0) > 0);
    EXPECT_TRUE(recvHandle->WaitCompletions(1));
    EXPECT_EQ(recvHandle->LastPayload(), std::string(msg));

    closesocket(client);
    closesocket(accepted);
    closesocket(listenSock);
    EXPECT_TRUE(recvHandle->WaitPendingZero());
    iocp.Stop();
}
