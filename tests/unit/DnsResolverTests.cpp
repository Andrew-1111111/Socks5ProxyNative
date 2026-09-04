#include "../TestFramework.h"

#include "../../dns/DnsClient.h"
#include "../../dns/DnsResolver.h"
#include "../../network/Iocp.h"

#include <memory>
#include <optional>
#include <string>

TEST(DnsResolver, CacheHitInvokesCallbackSynchronously) {
    IocpService iocp(2);
    EXPECT_TRUE(iocp.Start());

    auto resolver = std::make_shared<DnsResolver>(iocp, "127.0.0.1");
    EXPECT_TRUE(resolver->Start());

    DnsClient::DnsResult cached;
    cached.address = "203.0.113.55";
    cached.ttl = 120;
    cached.fromNetwork = true;
    resolver->Client().Cache("cached.example", cached);

    bool called = false;
    std::optional<std::string> got;
    resolver->ResolveAsync(
        "Cached.Example",
        [&](std::optional<std::string> ip) {
            called = true;
            got = std::move(ip);
        },
        true);

    EXPECT_TRUE(called);
    EXPECT_TRUE(got.has_value());
    EXPECT_EQ(*got, "203.0.113.55");

    resolver->Stop();
    iocp.Stop();
}

TEST(DnsResolver, NegativeCacheHitReturnsEmptySynchronously) {
    IocpService iocp(2);
    EXPECT_TRUE(iocp.Start());

    auto resolver = std::make_shared<DnsResolver>(iocp, "127.0.0.1");
    EXPECT_TRUE(resolver->Start());

    DnsClient::DnsResult neg;
    neg.address = std::nullopt;
    neg.ttl = 5;
    neg.fromNetwork = true;
    resolver->Client().Cache("missing.local", neg);

    bool called = false;
    std::optional<std::string> got = "sentinel";
    resolver->ResolveAsync(
        "missing.local",
        [&](std::optional<std::string> ip) {
            called = true;
            got = std::move(ip);
        },
        true);

    EXPECT_TRUE(called);
    EXPECT_FALSE(got.has_value());

    resolver->Stop();
    iocp.Stop();
}
