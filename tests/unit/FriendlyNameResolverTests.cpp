#include "../TestFramework.h"

#include "../../config/ProxyConfiguration.h"
#include "../../friendly/FriendlyNameResolver.h"
#include "../../network/Network.h"

#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

TEST(FriendlyNameResolver, MapsKnownAddresses) {
    std::vector<IPAddressMapping> mappings{
        {"192.168.0.10", "PC_1"},
        {" 192.168.0.11 ", " PC_2 "},
        {"bad", "ignored"},
        {"", "empty"},
    };
    FriendlyNameResolver resolver(mappings);
    EXPECT_EQ(resolver.FriendlySuffix("192.168.0.10"), " (PC_1)");
    EXPECT_EQ(resolver.FriendlySuffix("192.168.0.11"), " (PC_2)");
    EXPECT_TRUE(resolver.FriendlySuffix("10.0.0.1").empty());
}

TEST(FriendlyNameResolver, SockaddrLookup) {
    FriendlyNameResolver resolver({{"127.0.0.1", "Local"}});
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    EXPECT_EQ(resolver.FriendlySuffix(reinterpret_cast<sockaddr*>(&addr)), " (Local)");
    EXPECT_TRUE(resolver.FriendlySuffix(nullptr).empty());
}

TEST(FriendlyNameResolver, DuplicateKeepsLast) {
    FriendlyNameResolver resolver({
        {"10.0.0.5", "First"},
        {"10.0.0.5", "Second"},
    });
    EXPECT_EQ(resolver.FriendlySuffix("10.0.0.5"), " (Second)");
}
