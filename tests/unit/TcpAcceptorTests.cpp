#include "../TestFramework.h"

#include "../../network/Iocp.h"
#include "../../network/TcpAcceptor.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

TEST(TcpAcceptor, AcceptsOneClient) {
    IocpService iocp(2);
    EXPECT_TRUE(iocp.Start());

    SOCKET listenSock = IocpService::CreateTcpSocket(AF_INET);
    EXPECT_TRUE(listenSock != INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    EXPECT_TRUE(bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    EXPECT_TRUE(listen(listenSock, 8) == 0);

    int len = sizeof(addr);
    getsockname(listenSock, reinterpret_cast<sockaddr*>(&addr), &len);
    const uint16_t port = ntohs(addr.sin_port);

    std::mutex m;
    std::condition_variable cv;
    SOCKET accepted = INVALID_SOCKET;
    int acceptCount = 0;

    auto acceptor = std::make_shared<TcpAcceptor>(
        iocp, listenSock, AF_INET, [&](SOCKET client) {
            std::lock_guard lock(m);
            if (accepted == INVALID_SOCKET) {
                accepted = client;
            } else {
                closesocket(client);
            }
            ++acceptCount;
            cv.notify_all();
        });

    EXPECT_TRUE(acceptor->Start(2));

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    EXPECT_TRUE(client != INVALID_SOCKET);
    sockaddr_in dest = addr;
    dest.sin_port = htons(port);
    EXPECT_TRUE(connect(client, reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) == 0);

    {
        std::unique_lock lock(m);
        EXPECT_TRUE(cv.wait_for(lock, std::chrono::seconds(3), [&] {
            return acceptCount > 0;
        }));
        EXPECT_TRUE(accepted != INVALID_SOCKET);
    }

    closesocket(client);
    if (accepted != INVALID_SOCKET) {
        closesocket(accepted);
    }
    acceptor->Stop();
    closesocket(listenSock);
    iocp.Stop();
}
