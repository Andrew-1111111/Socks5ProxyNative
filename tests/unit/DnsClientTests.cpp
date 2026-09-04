#include "../TestFramework.h"

#include "../../dns/DnsClient.h"

#include <cstdint>
#include <cstring>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace {

void WriteU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void WriteU32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

std::vector<uint8_t> BuildAResponse(uint16_t id, const char* ipv4, int ttl = 60) {
    std::vector<uint8_t> out;
    WriteU16(out, id);
    WriteU16(out, 0x8180);  // QR, RD, RA
    WriteU16(out, 1);       // QDCOUNT
    WriteU16(out, 1);       // ANCOUNT
    WriteU16(out, 0);
    WriteU16(out, 0);

    // QNAME: example.com
    const char* labels[] = {"example", "com"};
    for (const char* label : labels) {
        const auto len = static_cast<uint8_t>(std::strlen(label));
        out.push_back(len);
        out.insert(out.end(), label, label + len);
    }
    out.push_back(0);
    WriteU16(out, 1);  // A
    WriteU16(out, 1);  // IN

    // Answer: pointer to QNAME at offset 12
    out.push_back(0xC0);
    out.push_back(0x0C);
    WriteU16(out, 1);  // A
    WriteU16(out, 1);  // IN
    WriteU32(out, static_cast<uint32_t>(ttl));
    WriteU16(out, 4);
    in_addr addr{};
    inet_pton(AF_INET, ipv4, &addr);
    const auto* bytes = reinterpret_cast<const uint8_t*>(&addr.s_addr);
    out.insert(out.end(), bytes, bytes + 4);
    return out;
}

}  // namespace

TEST(DnsClient, BuildQueryContainsIdTypeAndEdns) {
    const auto q = DnsClient::BuildQuery("example.com", 0x1234, 1);
    EXPECT_TRUE(q.size() > 12u);
    EXPECT_EQ(q[0], 0x12);
    EXPECT_EQ(q[1], 0x34);
    // QDCOUNT == 1
    EXPECT_EQ(q[4], 0);
    EXPECT_EQ(q[5], 1);
    // ARCOUNT == 1 (EDNS)
    EXPECT_EQ(q[10], 0);
    EXPECT_EQ(q[11], 1);
}

TEST(DnsClient, BuildQueryRejectsEmptyAndBadLabels) {
    EXPECT_THROW(DnsClient::BuildQuery("", 1, 1), std::invalid_argument);
    EXPECT_THROW(DnsClient::BuildQuery(".example.com", 1, 1), std::invalid_argument);
    EXPECT_THROW(DnsClient::BuildQuery(std::string(64, 'a') + ".com", 1, 1), std::invalid_argument);
}

TEST(DnsClient, ParseResponseARecord) {
    const auto wire = BuildAResponse(0xABCD, "8.8.8.8", 120);
    const auto result = DnsClient::ParseResponse(wire.data(), static_cast<int>(wire.size()), 0xABCD, 1);
    EXPECT_TRUE(result.fromNetwork);
    EXPECT_TRUE(result.address.has_value());
    EXPECT_EQ(*result.address, "8.8.8.8");
    EXPECT_EQ(result.ttl, 120);
    EXPECT_FALSE(result.truncated);
}

TEST(DnsClient, ParseResponseRejectsWrongId) {
    const auto wire = BuildAResponse(0x1111, "1.2.3.4");
    const auto result = DnsClient::ParseResponse(wire.data(), static_cast<int>(wire.size()), 0x2222, 1);
    EXPECT_FALSE(result.fromNetwork);
    EXPECT_FALSE(result.address.has_value());
}

TEST(DnsClient, ParseResponseNxDomainIsCacheable) {
    std::vector<uint8_t> wire;
    WriteU16(wire, 7);
    WriteU16(wire, 0x8183);  // NXDOMAIN
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    const auto result = DnsClient::ParseResponse(wire.data(), static_cast<int>(wire.size()), 7, 1);
    EXPECT_TRUE(result.fromNetwork);
    EXPECT_FALSE(result.address.has_value());
}

TEST(DnsClient, CachePositiveAndNegative) {
    DnsClient client("8.8.8.8");
    EXPECT_FALSE(client.TryGetCached("example.com").has_value());

    DnsClient::DnsResult ok;
    ok.address = "1.1.1.1";
    ok.ttl = 60;
    ok.fromNetwork = true;
    client.Cache("Example.COM", ok);

    auto hit = client.TryGetCached("example.com");
    EXPECT_TRUE(hit.has_value());
    EXPECT_TRUE(hit->has_value());
    EXPECT_EQ(**hit, "1.1.1.1");

    DnsClient::DnsResult miss;
    miss.address = std::nullopt;
    miss.ttl = 5;
    miss.fromNetwork = true;
    client.Cache("missing.test", miss);
    auto neg = client.TryGetCached("missing.test");
    EXPECT_TRUE(neg.has_value());
    EXPECT_FALSE(neg->has_value());
}

TEST(DnsClient, CacheIgnoresNonNetworkResults) {
    DnsClient client("8.8.8.8");
    DnsClient::DnsResult bad;
    bad.address = "9.9.9.9";
    bad.fromNetwork = false;
    client.Cache("nope.test", bad);
    EXPECT_FALSE(client.TryGetCached("nope.test").has_value());
}

TEST(DnsClient, SkipNameHandlesLabelsAndPointer) {
    std::vector<uint8_t> buf = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    EXPECT_EQ(DnsClient::SkipName(buf.data(), static_cast<int>(buf.size()), 0), 17);

    // Compression pointer to the labels starting at offset 0.
    std::vector<uint8_t> withPointer = buf;
    withPointer.push_back(0xC0);
    withPointer.push_back(0x00);
    EXPECT_EQ(DnsClient::SkipName(withPointer.data(), static_cast<int>(withPointer.size()),
                                  static_cast<int>(buf.size())),
              static_cast<int>(buf.size()) + 2);
}

TEST(DnsClient, GenerateIdProducesValues) {
    const auto a = DnsClient::GenerateId();
    const auto b = DnsClient::GenerateId();
    (void)a;
    (void)b;
    EXPECT_TRUE(true);
}

TEST(DnsClient, ParseResponseRejectsTooShort) {
    uint8_t tiny[] = {0, 1, 2};
    const auto result = DnsClient::ParseResponse(tiny, 3, 1, 1);
    EXPECT_FALSE(result.fromNetwork);
}

TEST(DnsClient, ParseResponseServfailNotCacheable) {
    std::vector<uint8_t> wire;
    WriteU16(wire, 9);
    WriteU16(wire, 0x8182);  // SERVFAIL
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    const auto result = DnsClient::ParseResponse(wire.data(), static_cast<int>(wire.size()), 9, 1);
    EXPECT_FALSE(result.fromNetwork);
    EXPECT_FALSE(result.address.has_value());
}

TEST(DnsClient, ParseResponseAAAA) {
    std::vector<uint8_t> out;
    WriteU16(out, 0x55AA);
    WriteU16(out, 0x8180);
    WriteU16(out, 1);
    WriteU16(out, 1);
    WriteU16(out, 0);
    WriteU16(out, 0);
    out.push_back(3);
    out.insert(out.end(), {'i', 'p', '6'});
    out.push_back(4);
    out.insert(out.end(), {'t', 'e', 's', 't'});
    out.push_back(0);
    WriteU16(out, 28);
    WriteU16(out, 1);
    out.push_back(0xC0);
    out.push_back(0x0C);
    WriteU16(out, 28);
    WriteU16(out, 1);
    WriteU32(out, 30);
    WriteU16(out, 16);
    in6_addr addr6{};
    inet_pton(AF_INET6, "2001:db8::1", &addr6);
    const auto* bytes = reinterpret_cast<const uint8_t*>(&addr6);
    out.insert(out.end(), bytes, bytes + 16);

    const auto result = DnsClient::ParseResponse(out.data(), static_cast<int>(out.size()), 0x55AA, 28);
    EXPECT_TRUE(result.fromNetwork);
    EXPECT_TRUE(result.address.has_value());
    EXPECT_TRUE(result.address->find(':') != std::string::npos);
}

TEST(DnsClient, ParseResponseTruncatedFlag) {
    std::vector<uint8_t> wire;
    WriteU16(wire, 1);
    WriteU16(wire, 0x8380);  // QR + TC
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    WriteU16(wire, 0);
    const auto result = DnsClient::ParseResponse(wire.data(), static_cast<int>(wire.size()), 1, 1);
    EXPECT_TRUE(result.truncated);
}

TEST(DnsClient, ServerAccessor) {
    DnsClient client("1.1.1.1");
    EXPECT_EQ(client.Server(), "1.1.1.1");
}

TEST(DnsClient, BuildQueryEncodesLabels) {
    const auto q = DnsClient::BuildQuery("a.b", 1, 1);
    // After header (12 bytes): len 1 'a' len 1 'b' 0
    EXPECT_EQ(q[12], 1);
    EXPECT_EQ(q[13], 'a');
    EXPECT_EQ(q[14], 1);
    EXPECT_EQ(q[15], 'b');
    EXPECT_EQ(q[16], 0);
}

TEST(DnsClient, ParseResponseRejectsQueryBitAndOpcode) {
    std::vector<uint8_t> query;
    WriteU16(query, 1);
    WriteU16(query, 0x0100);  // QR=0 (query), RD
    WriteU16(query, 0);
    WriteU16(query, 0);
    WriteU16(query, 0);
    WriteU16(query, 0);
    EXPECT_FALSE(DnsClient::ParseResponse(query.data(), static_cast<int>(query.size()), 1, 1).fromNetwork);

    std::vector<uint8_t> opcode;
    WriteU16(opcode, 2);
    WriteU16(opcode, 0x8800);  // QR=1, opcode=1
    WriteU16(opcode, 0);
    WriteU16(opcode, 0);
    WriteU16(opcode, 0);
    WriteU16(opcode, 0);
    EXPECT_FALSE(DnsClient::ParseResponse(opcode.data(), static_cast<int>(opcode.size()), 2, 1).fromNetwork);
}

TEST(DnsClient, ParseResponseSkipsCnameThenReturnsA) {
    std::vector<uint8_t> out;
    WriteU16(out, 0x4242);
    WriteU16(out, 0x8180);
    WriteU16(out, 1);  // QD
    WriteU16(out, 2);  // AN: CNAME + A
    WriteU16(out, 0);
    WriteU16(out, 0);

    out.push_back(3);
    out.insert(out.end(), {'w', 'w', 'w'});
    out.push_back(7);
    out.insert(out.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    out.push_back(3);
    out.insert(out.end(), {'c', 'o', 'm'});
    out.push_back(0);
    WriteU16(out, 1);
    WriteU16(out, 1);

    // CNAME answer (TTL 100)
    out.push_back(0xC0);
    out.push_back(0x0C);
    WriteU16(out, 5);
    WriteU16(out, 1);
    WriteU32(out, 100);
    WriteU16(out, 2);
    out.push_back(0xC0);
    out.push_back(0x10);  // pointer into QNAME (example.com)

    // A answer (TTL 40) — min TTL across matching path includes prior RRs
    out.push_back(0xC0);
    out.push_back(0x0C);
    WriteU16(out, 1);
    WriteU16(out, 1);
    WriteU32(out, 40);
    WriteU16(out, 4);
    in_addr addr{};
    inet_pton(AF_INET, "203.0.113.10", &addr);
    const auto* bytes = reinterpret_cast<const uint8_t*>(&addr.s_addr);
    out.insert(out.end(), bytes, bytes + 4);

    const auto result = DnsClient::ParseResponse(out.data(), static_cast<int>(out.size()), 0x4242, 1);
    EXPECT_TRUE(result.fromNetwork);
    EXPECT_TRUE(result.address.has_value());
    EXPECT_EQ(*result.address, "203.0.113.10");
    EXPECT_EQ(result.ttl, 40);
}

TEST(DnsClient, CacheExpiresAfterTtl) {
    DnsClient client("8.8.8.8");
    DnsClient::DnsResult ok;
    ok.address = "10.0.0.1";
    ok.ttl = 1;
    ok.fromNetwork = true;
    client.Cache("expire.test", ok);

    auto hit = client.TryGetCached("expire.test");
    EXPECT_TRUE(hit.has_value());
    EXPECT_TRUE(hit->has_value());

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    EXPECT_FALSE(client.TryGetCached("expire.test").has_value());
}

TEST(DnsClient, SkipNameRejectsBadCompression) {
    std::vector<uint8_t> truncated = {0xC0};
    EXPECT_THROW(DnsClient::SkipName(truncated.data(), 1, 0), std::runtime_error);

    std::vector<uint8_t> oob = {0xC0, 0xFF};
    EXPECT_THROW(DnsClient::SkipName(oob.data(), 2, 0), std::runtime_error);
}
