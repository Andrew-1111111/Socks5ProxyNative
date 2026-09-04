#pragma once

#include "../dns/DnsResolver.h"
#include "../friendly/FriendlyNameResolver.h"
#include "../network/TcpAcceptor.h"

#include <network/Iocp.h>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <semaphore>
#include <unordered_set>
#include <WinSock2.h>
#include <ws2def.h>

class Socks5Session;

class ProxyServer {
public:
    explicit ProxyServer(FriendlyNameResolver& resolver);
    ~ProxyServer();

    void Start(std::atomic<bool>& stopFlag);
    void Stop();

    IocpService& Iocp() { return iocp_; }
    DnsResolver& Dns() { return *dns_; }
    FriendlyNameResolver& Resolver() { return resolver_; }

    void OnSessionClosed(std::shared_ptr<Socks5Session> session, bool releaseSlot);
    void RetainSession(const std::shared_ptr<Socks5Session>& session);

private:
    void OnAccept(SOCKET client);

    FriendlyNameResolver& resolver_;
    IocpService iocp_;
    std::shared_ptr<DnsResolver> dns_;

    SOCKET listenSocket_ = INVALID_SOCKET;
    int listenFamily_ = AF_INET;
    std::shared_ptr<TcpAcceptor> acceptor_;

    std::mutex sessionsMutex_;
    std::unordered_set<std::shared_ptr<Socks5Session>> sessions_;
    std::condition_variable sessionsCv_;

    std::unique_ptr<std::counting_semaphore<1048576>> connectionSlots_;
    std::atomic<bool> stopping_{false};
};
