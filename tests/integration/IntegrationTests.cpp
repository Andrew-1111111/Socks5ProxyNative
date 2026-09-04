#include "../TestFramework.h"
#include "IntegrationTestSupport.h"

#include <string>
#include <vector>

TEST(Integration, ConnectAndRelayEcho) {
    integ::NetworkConfigGuard guard;
    integ::TcpEchoServer echo;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort);

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeNoAuth(client));

    uint8_t reply = 0xFF;
    EXPECT_TRUE(integ::Socks5ConnectIpv4(client, "127.0.0.1", echo.Port(), reply));
    EXPECT_EQ(reply, socks5::ReplyCode::Succeeded);

    const char payload[] = "hello-socks5-integration";
    EXPECT_TRUE(integ::SendAll(client, payload, static_cast<int>(sizeof(payload) - 1)));
    char echoed[64]{};
    EXPECT_TRUE(integ::RecvExact(client, echoed, static_cast<int>(sizeof(payload) - 1)));
    EXPECT_EQ(std::string(echoed, sizeof(payload) - 1), std::string(payload));

    closesocket(client);
}

TEST(Integration, RejectUnsupportedSocksVersion) {
    integ::NetworkConfigGuard guard;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort);

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    const uint8_t req[] = {0x04, 0x01, 0x00};
    EXPECT_TRUE(integ::SendAll(client, req, sizeof(req)));

    char buf[16];
    const int n = recv(client, buf, sizeof(buf), 0);
    // Session closes without a valid SOCKS5 method reply.
    EXPECT_TRUE(n <= 0);
    closesocket(client);
}

TEST(Integration, RejectWhenAuthRequiredButClientOffersNoAuth) {
    integ::NetworkConfigGuard guard;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort, 0, "user", "pass");

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    const uint8_t req[] = {0x05, 0x01, 0x00};
    uint8_t resp[2]{};
    EXPECT_TRUE(integ::SendAll(client, req, sizeof(req)));
    EXPECT_TRUE(integ::RecvExact(client, resp, 2));
    EXPECT_EQ(resp[0], 0x05);
    EXPECT_EQ(resp[1], socks5::AuthMethod::NoAcceptableMethods);

    char buf[8];
    const int n = recv(client, buf, sizeof(buf), 0);
    EXPECT_TRUE(n <= 0);
    closesocket(client);
}

TEST(Integration, UsernamePasswordAuthThenRelay) {
    integ::NetworkConfigGuard guard;
    integ::TcpEchoServer echo;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort, 0, "alice", "secret");

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeUserPass(client));
    EXPECT_TRUE(integ::Socks5UserPassAuth(client, "alice", "secret"));

    uint8_t reply = 0xFF;
    EXPECT_TRUE(integ::Socks5ConnectIpv4(client, "127.0.0.1", echo.Port(), reply));
    EXPECT_EQ(reply, socks5::ReplyCode::Succeeded);

    const char payload[] = "auth-ok";
    EXPECT_TRUE(integ::SendAll(client, payload, static_cast<int>(sizeof(payload) - 1)));
    char echoed[32]{};
    EXPECT_TRUE(integ::RecvExact(client, echoed, static_cast<int>(sizeof(payload) - 1)));
    EXPECT_EQ(std::string(echoed, sizeof(payload) - 1), std::string(payload));
    closesocket(client);
}

TEST(Integration, UsernamePasswordAuthFailure) {
    integ::NetworkConfigGuard guard;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort, 0, "alice", "secret");

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeUserPass(client));

    const uint8_t badAuth[] = {0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x03, 'b', 'a', 'd'};
    uint8_t resp[2]{};
    EXPECT_TRUE(integ::SendAll(client, badAuth, sizeof(badAuth)));
    EXPECT_TRUE(integ::RecvExact(client, resp, 2));
    EXPECT_EQ(resp[0], 0x01);
    EXPECT_EQ(resp[1], socks5::AuthProtocol::Failure);

    char buf[8];
    EXPECT_TRUE(recv(client, buf, sizeof(buf), 0) <= 0);
    closesocket(client);
}

TEST(Integration, ConnectUnreachableHostFails) {
    integ::NetworkConfigGuard guard;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort);

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeNoAuth(client));

    // TEST-NET-1, should not be routable; connect timeout is 2s in ScopedProxy.
    uint8_t reply = 0x00;
    EXPECT_TRUE(integ::Socks5ConnectIpv4(client, "192.0.2.1", 9, reply));
    EXPECT_TRUE(reply != socks5::ReplyCode::Succeeded);
    closesocket(client);
}

TEST(Integration, UnsupportedCommandBind) {
    integ::NetworkConfigGuard guard;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort);

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeNoAuth(client));

    uint8_t req[10]{};
    req[0] = 0x05;
    req[1] = socks5::Command::Bind;
    req[2] = 0x00;
    req[3] = socks5::AddressType::IPv4;
    EXPECT_TRUE(integ::SendAll(client, req, sizeof(req)));

    uint8_t resp[10]{};
    EXPECT_TRUE(integ::RecvExact(client, resp, 4));
    EXPECT_EQ(resp[0], 0x05);
    EXPECT_EQ(resp[1], socks5::ReplyCode::CommandNotSupported);
    closesocket(client);
}

TEST(Integration, UdpAssociateReturnsRelayEndpoint) {
    integ::NetworkConfigGuard guard;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort);

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeNoAuth(client));

    uint8_t reply = 0xFF;
    sockaddr_storage relay{};
    int relayLen = 0;
    EXPECT_TRUE(integ::Socks5UdpAssociate(client, reply, relay, relayLen));
    EXPECT_EQ(reply, socks5::ReplyCode::Succeeded);
    EXPECT_EQ(relay.ss_family, AF_INET);
    const auto* v4 = reinterpret_cast<sockaddr_in*>(&relay);
    EXPECT_TRUE(ntohs(v4->sin_port) != 0);

    // Keep TCP control channel open briefly, then close (ends UDP associate).
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    closesocket(client);
}

TEST(Integration, MaxConnectionsLimitsConcurrentClients) {
    integ::NetworkConfigGuard guard;
    integ::TcpEchoServer echo;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort, /*maxConnections*/ 1);

    // Give AcceptEx/session startup a moment after limited-slot start.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    SOCKET first = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(first != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeNoAuth(first));
    uint8_t reply = 0xFF;
    EXPECT_TRUE(integ::Socks5ConnectIpv4(first, "127.0.0.1", echo.Port(), reply));
    EXPECT_EQ(reply, socks5::ReplyCode::Succeeded);

    SOCKET second = integ::ConnectTcp("127.0.0.1", proxy.Port(), 2000);
    if (second != INVALID_SOCKET) {
        const uint8_t req[] = {0x05, 0x01, 0x00};
        (void)integ::SendAll(second, req, sizeof(req));
        char buf[8];
        const int n = recv(second, buf, sizeof(buf), 0);
        EXPECT_TRUE(n <= 0);
        closesocket(second);
    }

    closesocket(first);
}

TEST(Integration, DomainAtypConnectToIpv4Literal) {
    integ::NetworkConfigGuard guard;
    integ::TcpEchoServer echo;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort);

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeNoAuth(client));

    // ATYP=DOMAIN with an IPv4 literal — StartConnect parses it as IP (no DNS).
    const std::string host = "127.0.0.1";
    std::vector<uint8_t> req;
    req.push_back(0x05);
    req.push_back(socks5::Command::Connect);
    req.push_back(0x00);
    req.push_back(socks5::AddressType::DomainName);
    req.push_back(static_cast<uint8_t>(host.size()));
    req.insert(req.end(), host.begin(), host.end());
    const uint16_t port = echo.Port();
    req.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    req.push_back(static_cast<uint8_t>(port & 0xFF));

    EXPECT_TRUE(integ::SendAll(client, req.data(), static_cast<int>(req.size())));
    uint8_t resp[10]{};
    EXPECT_TRUE(integ::RecvExact(client, resp, 10));
    EXPECT_EQ(resp[0], 0x05);
    EXPECT_EQ(resp[1], socks5::ReplyCode::Succeeded);

    const char payload[] = "domain-atyp";
    EXPECT_TRUE(integ::SendAll(client, payload, static_cast<int>(sizeof(payload) - 1)));
    char echoed[32]{};
    EXPECT_TRUE(integ::RecvExact(client, echoed, static_cast<int>(sizeof(payload) - 1)));
    EXPECT_EQ(std::string(echoed, sizeof(payload) - 1), std::string(payload));
    closesocket(client);
}

TEST(Integration, RejectUnsupportedAddressType) {
    integ::NetworkConfigGuard guard;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort);

    SOCKET client = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(client != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeNoAuth(client));

    // ATYP 0xFF is not supported; session replies and closes.
    const uint8_t req[] = {0x05, socks5::Command::Connect, 0x00, 0xFF};
    EXPECT_TRUE(integ::SendAll(client, req, sizeof(req)));

    uint8_t resp[4]{};
    EXPECT_TRUE(integ::RecvExact(client, resp, 4));
    EXPECT_EQ(resp[0], 0x05);
    EXPECT_EQ(resp[1], socks5::ReplyCode::AddressTypeNotSupported);
    closesocket(client);
}

TEST(Integration, UdpAssociateRelaysEchoPayload) {
    integ::NetworkConfigGuard guard;
    integ::UdpEchoServer echo;
    const uint16_t proxyPort = integ::FindFreeTcpPort();
    integ::ScopedProxy proxy(proxyPort);

    SOCKET control = integ::ConnectTcp("127.0.0.1", proxy.Port());
    EXPECT_TRUE(control != INVALID_SOCKET);
    EXPECT_TRUE(integ::Socks5HandshakeNoAuth(control));

    uint8_t reply = 0xFF;
    sockaddr_storage relay{};
    int relayLen = 0;
    EXPECT_TRUE(integ::Socks5UdpAssociate(control, reply, relay, relayLen));
    EXPECT_EQ(reply, socks5::ReplyCode::Succeeded);

    auto* relayV4 = reinterpret_cast<sockaddr_in*>(&relay);
    if (relayV4->sin_addr.s_addr == 0) {
        inet_pton(AF_INET, "127.0.0.1", &relayV4->sin_addr);
    }

    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    EXPECT_TRUE(udp != INVALID_SOCKET);
    integ::SetSocketTimeouts(udp, 3000);

    const char payload[] = "udp-echo-via-socks";
    auto packet = integ::BuildSocksUdpIpv4Request("127.0.0.1", echo.Port(), payload,
                                                  sizeof(payload) - 1);
    EXPECT_TRUE(sendto(udp, reinterpret_cast<const char*>(packet.data()),
                       static_cast<int>(packet.size()), 0,
                       reinterpret_cast<sockaddr*>(&relay), relayLen) > 0);

    uint8_t resp[512]{};
    const int n = recvfrom(udp, reinterpret_cast<char*>(resp), sizeof(resp), 0, nullptr, nullptr);
    EXPECT_TRUE(n > 10);
    std::string echoed;
    EXPECT_TRUE(integ::ParseSocksUdpIpv4Reply(resp, n, echoed));
    EXPECT_EQ(echoed, std::string(payload));

    closesocket(udp);
    closesocket(control);
}
