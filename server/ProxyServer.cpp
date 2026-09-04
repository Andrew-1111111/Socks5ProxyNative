#include "ProxyServer.h"

#include "../config/NetworkConfiguration.h"
#include "../network/Network.h"
#include "../utils/Logger.h"
#include "protocol/Socks5Session.h"
#include <dns/DnsResolver.h>
#include <friendly/FriendlyNameResolver.h>
#include <network/Iocp.h>
#include <network/TcpAcceptor.h>

#include <atomic>
#include <chrono>
#include <exception>
#include <memory>
#include <mutex>
#include <semaphore>
#include <stdexcept>
#include <thread>
#include <vector>
#include <Windows.h>
#include <WinSock2.h>
#include <ws2def.h>

ProxyServer::ProxyServer(FriendlyNameResolver& resolver)
    : resolver_(resolver) {}

ProxyServer::~ProxyServer() {
    Stop();
}

void ProxyServer::Start(std::atomic<bool>& stopFlag) {
    if (!iocp_.Start()) {
        throw std::runtime_error("Failed to start IOCP service");
    }

    dns_ = std::make_shared<DnsResolver>(iocp_, NetworkConfiguration::DnsServer);
    if (!dns_->Start()) {
        throw std::runtime_error("Failed to start DNS resolver");
    }

    sockaddr_storage listenAddr{};
    int listenLen = 0;
    if (!NetworkConfiguration::FillListenAddress(listenAddr, listenLen)) {
        throw std::runtime_error("Invalid listen address");
    }
    listenFamily_ = listenAddr.ss_family;

    listenSocket_ = IocpService::CreateTcpSocket(listenFamily_);
    if (listenSocket_ == INVALID_SOCKET) {
        throw std::runtime_error("Failed to create listen socket");
    }

    BOOL reuse = TRUE;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    if (bind(listenSocket_, reinterpret_cast<sockaddr*>(&listenAddr), listenLen) != 0) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        throw std::runtime_error("Failed to bind listen socket");
    }

    if (listen(listenSocket_, SOMAXCONN) != 0) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        throw std::runtime_error("Failed to listen");
    }

    if (NetworkConfiguration::MaxConnections > 0) {
        connectionSlots_ = std::make_unique<std::counting_semaphore<1048576>>(
            NetworkConfiguration::MaxConnections);
    }

    sockaddr_storage local{};
    int localLen = sizeof(local);
    getsockname(listenSocket_, reinterpret_cast<sockaddr*>(&local), &localLen);

    Logger::Instance().Info("SOCKS5 proxy server started on: {LocalEndPoint}{Friendly}",
                            NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&local)),
                            resolver_.FriendlySuffix(reinterpret_cast<sockaddr*>(&local)));
    Logger::Instance().Info("------------------------------------------------");

    acceptor_ = std::make_shared<TcpAcceptor>(
        iocp_, listenSocket_, listenFamily_,
        [this](SOCKET client) { OnAccept(client); });

    if (!acceptor_->Start(16)) {
        throw std::runtime_error("Failed to start AcceptEx acceptor");
    }

    while (!stopFlag && !stopping_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    Stop();
    Logger::Instance().Info("SOCKS5 proxy server stopped.");
}

void ProxyServer::OnAccept(SOCKET client) {
    if (stopping_ || client == INVALID_SOCKET) {
        if (client != INVALID_SOCKET) closesocket(client);
        return;
    }

    bool slotHeld = false;
    if (connectionSlots_) {
        if (!connectionSlots_->try_acquire()) {
            closesocket(client);
            return;
        }
        slotHeld = true;
    }

    try {
        auto session = std::make_shared<Socks5Session>(iocp_, *this, client, *dns_, resolver_, slotHeld);
        RetainSession(session);
        if (!session->Start()) {
            session->Close();
        }
    } catch (const std::exception& ex) {
        closesocket(client);
        if (slotHeld && connectionSlots_) connectionSlots_->release();
        Logger::Instance().Error("Error accepting client connection: {Error}", ex.what());
    }
}

void ProxyServer::RetainSession(const std::shared_ptr<Socks5Session>& session) {
    std::lock_guard lock(sessionsMutex_);
    sessions_.insert(session);
}

void ProxyServer::OnSessionClosed(std::shared_ptr<Socks5Session> session, bool releaseSlot) {
    {
        std::lock_guard lock(sessionsMutex_);
        sessions_.erase(session);
        if (sessions_.empty()) {
            sessionsCv_.notify_all();
        }
    }
    if (releaseSlot && connectionSlots_) {
        connectionSlots_->release();
    }
}

void ProxyServer::Stop() {
    if (stopping_.exchange(true)) {
        return;
    }

    if (acceptor_) {
        acceptor_->Stop();
    }

    if (listenSocket_ != INVALID_SOCKET) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }
    if (acceptor_) {
        acceptor_->WaitPendingZero(-1);
        acceptor_.reset();
    }

    std::vector<std::shared_ptr<Socks5Session>> snapshot;
    {
        std::lock_guard lock(sessionsMutex_);
        snapshot.assign(sessions_.begin(), sessions_.end());
    }
    Logger::Instance().Info("Waiting for {Count} active connections to finish.",
                            static_cast<int>(snapshot.size()));
    for (auto& s : snapshot) {
        s->Close();
    }
    for (auto& s : snapshot) {
        s->WaitPendingZero(-1);
    }

    {
        std::unique_lock lock(sessionsMutex_);
        sessionsCv_.wait_for(lock, std::chrono::seconds(10), [this] {
            return sessions_.empty();
        });
        if (!sessions_.empty()) {
            Logger::Instance().Warning("Some connections did not close gracefully within timeout.");
            std::vector<std::shared_ptr<Socks5Session>> leftover(sessions_.begin(), sessions_.end());
            sessions_.clear();
            lock.unlock();
            for (auto& s : leftover) {
                if (s) {
                    s->Close();
                    s->WaitPendingZero(3000);
                }
            }
            // Slots for leftover sessions were not released via OnSessionClosed if already closed;
            // Close() is idempotent and releases only once.
        }
    }

    if (dns_) {
        dns_->Stop();
        dns_->WaitPendingZero(-1);
        dns_.reset();
    }
    iocp_.Stop();
}
