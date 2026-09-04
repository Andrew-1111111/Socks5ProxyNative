#include "../TestFramework.h"

#include "../../network/Network.h"

#include <cstring>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

TEST(NetworkUtils, IsAnyAddress) {
    EXPECT_TRUE(NetworkUtils::IsAnyAddress("0.0.0.0"));
    EXPECT_TRUE(NetworkUtils::IsAnyAddress("::"));
    EXPECT_TRUE(NetworkUtils::IsAnyAddress(""));
    EXPECT_FALSE(NetworkUtils::IsAnyAddress("127.0.0.1"));
    EXPECT_FALSE(NetworkUtils::IsAnyAddress("::1"));
}

TEST(NetworkUtils, ParseIPv4) {
    sockaddr_storage storage{};
    int family = 0;
    EXPECT_TRUE(NetworkUtils::ParseIP("192.168.1.10", storage, family));
    EXPECT_EQ(family, AF_INET);
    EXPECT_EQ(NetworkUtils::IPToString(reinterpret_cast<sockaddr*>(&storage)), "192.168.1.10");
}

TEST(NetworkUtils, ParseIPv6) {
    sockaddr_storage storage{};
    int family = 0;
    EXPECT_TRUE(NetworkUtils::ParseIP("2001:db8::1", storage, family));
    EXPECT_EQ(family, AF_INET6);
    const std::string ip = NetworkUtils::IPToString(reinterpret_cast<sockaddr*>(&storage));
    EXPECT_FALSE(ip.empty());
    EXPECT_TRUE(ip.find(':') != std::string::npos);
}

TEST(NetworkUtils, ParseInvalidIpFails) {
    sockaddr_storage storage{};
    int family = 0;
    EXPECT_FALSE(NetworkUtils::ParseIP("not-an-ip", storage, family));
    EXPECT_FALSE(NetworkUtils::ParseIP("999.999.999.999", storage, family));
}

TEST(NetworkUtils, EndpointToStringIpv4) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1080);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    EXPECT_EQ(NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&addr)), "127.0.0.1:1080");
}

TEST(NetworkUtils, EndpointToStringIpv6) {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(1080);
    inet_pton(AF_INET6, "::1", &addr.sin6_addr);
    const std::string ep = NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&addr));
    EXPECT_EQ(ep.front(), '[');
    EXPECT_TRUE(ep.find("]:1080") != std::string::npos);
}

TEST(NetworkUtils, EndpointKeyEqualityAndHash) {
    sockaddr_storage a{};
    sockaddr_storage b{};
    int family = 0;
    EXPECT_TRUE(NetworkUtils::ParseIP("10.0.0.1", a, family));
    EXPECT_TRUE(NetworkUtils::ParseIP("10.0.0.1", b, family));
    reinterpret_cast<sockaddr_in*>(&a)->sin_port = htons(1);
    reinterpret_cast<sockaddr_in*>(&b)->sin_port = htons(1);

    const auto ka = EndpointKey::From(a);
    const auto kb = EndpointKey::From(b);
    EXPECT_TRUE(ka == kb);
    EXPECT_EQ(EndpointKeyHash{}(ka), EndpointKeyHash{}(kb));

    reinterpret_cast<sockaddr_in*>(&b)->sin_port = htons(2);
    const auto kc = EndpointKey::From(b);
    EXPECT_FALSE(ka == kc);
}

TEST(NetworkUtils, EndpointToStringNullAndUnknown) {
    EXPECT_EQ(NetworkUtils::EndpointToString(nullptr), "Unknown");
    sockaddr_storage storage{};
    storage.ss_family = AF_UNSPEC;
    EXPECT_EQ(NetworkUtils::EndpointToString(reinterpret_cast<sockaddr*>(&storage)), "Unknown");
}

TEST(NetworkUtils, IsIPAddressAvailableAnyAndLoopback) {
    EXPECT_TRUE(NetworkUtils::IsIPAddressAvailable("0.0.0.0"));
    EXPECT_TRUE(NetworkUtils::IsIPAddressAvailable("::"));
    EXPECT_TRUE(NetworkUtils::IsIPAddressAvailable("127.0.0.1"));
    EXPECT_FALSE(NetworkUtils::IsIPAddressAvailable("not-an-ip"));
}

TEST(NetworkUtils, IsPortAvailableEphemeral) {
    // Port 0 binding probe should succeed on a healthy stack.
    EXPECT_TRUE(NetworkUtils::IsPortAvailable(0));
}

TEST(NetworkUtils, IsIPv6AvailableLoopback) {
    EXPECT_TRUE(NetworkUtils::IsIPv6Available("::1"));
    EXPECT_FALSE(NetworkUtils::IsIPv6Available("127.0.0.1"));
}

TEST(NetworkUtils, EndpointKeyFromEmptyFamily) {
    sockaddr_storage storage{};
    storage.ss_family = AF_UNSPEC;
    const auto key = EndpointKey::From(storage);
    EXPECT_EQ(key.len, 0);
}

TEST(NetworkUtils, CheckDnsRejectsInvalidServer) {
    EXPECT_FALSE(NetworkUtils::CheckDns("not-a-dns-ip", "127.0.0.1", 200, 1, 0));
    EXPECT_FALSE(NetworkUtils::CheckDns("", "127.0.0.1", 200, 1, 0));
}
