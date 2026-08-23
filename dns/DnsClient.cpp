#include "DnsClient.h"

#include <chrono>
#include <climits>
#include <cctype>
#include <cstdint>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace {

long long NowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

uint16_t ReadU16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t ReadU32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

void WriteU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

std::string ToLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

DnsClient::DnsClient(const std::string& dnsServer) : dnsServer_(dnsServer) {}

std::optional<std::optional<std::string>> DnsClient::TryGetCached(const std::string& domainRaw) {
    if (domainRaw.empty()) {
        return std::nullopt;
    }
    const std::string domain = ToLower(domainRaw);
    std::lock_guard lock(cacheMutex_);
    auto it = cache_.find(domain);
    if (it == cache_.end() || it->second.expiryMs <= NowMs()) {
        return std::nullopt;
    }
    if (it->second.negative) {
        return std::optional<std::string>{};
    }
    return it->second.address;
}

std::vector<uint8_t> DnsClient::BuildQuery(const std::string& domain, uint16_t id, uint16_t type) {
    if (domain.empty() || domain.size() > 253) {
        throw std::invalid_argument("Invalid domain length");
    }

    std::vector<uint8_t> out;
    out.reserve(256);
    WriteU16(out, id);
    WriteU16(out, 0x0100);
    WriteU16(out, 1);
    WriteU16(out, 0);
    WriteU16(out, 0);
    WriteU16(out, 1); // ARCOUNT = 1 (EDNS0 OPT)

    std::stringstream ss(domain);
    std::string label;
    while (std::getline(ss, label, '.')) {
        if (label.empty() || label.size() > 63) {
            throw std::invalid_argument("Invalid domain label");
        }
        out.push_back(static_cast<uint8_t>(label.size()));
        out.insert(out.end(), label.begin(), label.end());
    }
    out.push_back(0);
    if (out.size() - 12 > 255) {
        throw std::invalid_argument("Encoded domain name is too long");
    }
    WriteU16(out, type);
    WriteU16(out, 1);

    // EDNS0 OPT RR: allow larger UDP answers (reduces pointless TCP fallback).
    out.push_back(0);       // root name
    WriteU16(out, 41);      // TYPE OPT
    WriteU16(out, 4096);    // UDP payload size
    out.push_back(0);       // extended RCODE
    out.push_back(0);       // version
    WriteU16(out, 0);       // Z flags
    WriteU16(out, 0);       // RDLEN
    return out;
}

DnsClient::DnsResult DnsClient::ParseResponse(const uint8_t* buffer, int length, uint16_t expectedId, uint16_t expectedType) {
    if (length < 12) return DnsResult::Invalid();
    if (ReadU16(buffer) != expectedId) return DnsResult::Invalid();

    const uint16_t flags = ReadU16(buffer + 2);
    if ((flags & 0x8000) == 0 || (flags & 0x7800) != 0) {
        return DnsResult::Invalid();
    }
    const bool truncated = (flags & 0x0200) != 0;
    const int rcode = flags & 0xF;
    if (rcode != 0) {
        // Cache only NXDOMAIN; transient codes (SERVFAIL/REFUSED) must not poison the cache.
        const bool cacheable = (rcode == 3);
        return DnsResult{std::nullopt, 30, truncated, cacheable};
    }

    const uint16_t qd = ReadU16(buffer + 4);
    const uint16_t an = ReadU16(buffer + 6);
    if (qd > 64 || an > 64) {
        return DnsResult::Invalid();
    }
    int pos = 12;

    auto truncatedEmpty = [&]() {
        // Preserve TC so caller can fall back to TCP instead of treating as hard failure.
        return DnsResult{std::nullopt, 30, true, true};
    };

    try {
        for (int i = 0; i < qd; ++i) {
            pos = SkipName(buffer, length, pos) + 4;
            if (pos > length) {
                return truncated ? truncatedEmpty() : DnsResult::Invalid();
            }
        }

        int minTtl = INT_MAX;
        for (int i = 0; i < an; ++i) {
            pos = SkipName(buffer, length, pos);
            if (pos + 10 > length) {
                return truncated ? truncatedEmpty() : DnsResult::Invalid();
            }
            const uint16_t type = ReadU16(buffer + pos); pos += 2;
            const uint16_t dnsClass = ReadU16(buffer + pos); pos += 2;
            const uint32_t ttl = ReadU32(buffer + pos); pos += 4;
            const uint16_t rdlen = ReadU16(buffer + pos); pos += 2;
            const int ttlSeconds =
                ttl > static_cast<uint32_t>(INT_MAX) ? INT_MAX : static_cast<int>(ttl);
            if (ttlSeconds < minTtl) minTtl = ttlSeconds;

            if (pos + rdlen > length) {
                return truncated ? truncatedEmpty() : DnsResult::Invalid();
            }

            if (dnsClass == 1 && type == expectedType) {
                if (type == 1 && rdlen == 4) {
                    char ip[INET_ADDRSTRLEN]{};
                    inet_ntop(AF_INET, buffer + pos, ip, sizeof(ip));
                    return DnsResult{std::string(ip), minTtl == INT_MAX ? 30 : minTtl, truncated, true};
                }
                if (type == 28 && rdlen == 16) {
                    char ip[INET6_ADDRSTRLEN]{};
                    inet_ntop(AF_INET6, buffer + pos, ip, sizeof(ip));
                    return DnsResult{std::string(ip), minTtl == INT_MAX ? 30 : minTtl, truncated, true};
                }
            }
            pos += rdlen;
        }
        return DnsResult{std::nullopt, minTtl == INT_MAX ? 30 : minTtl, truncated, true};
    } catch (...) {
        return truncated ? truncatedEmpty() : DnsResult::Invalid();
    }
}

int DnsClient::SkipName(const uint8_t* buffer, int length, int pos) {
    int jumps = 0;
    while (true) {
        if (pos >= length) throw std::runtime_error("Invalid DNS name");
        const uint8_t len = buffer[pos];
        if (len == 0) return pos + 1;
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= length) throw std::runtime_error("Invalid DNS compression");
            const int pointer = ((len & 0x3F) << 8) | buffer[pos + 1];
            if (pointer >= length) throw std::runtime_error("Invalid DNS compression offset");
            if (++jumps > 20) throw std::runtime_error("Compression loop");
            return pos + 2;
        }
        if (pos + len + 1 > length) throw std::runtime_error("Invalid DNS name length");
        pos += len + 1;
    }
}

uint16_t DnsClient::GenerateId() {
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, 65535);
    return static_cast<uint16_t>(dist(rng));
}

void DnsClient::Cache(const std::string& domain, const DnsResult& result) {
    if (!result.fromNetwork) {
        return;
    }

    std::lock_guard lock(cacheMutex_);
    if (cache_.size() >= 10000) {
        int dropped = 0;
        for (auto it = cache_.begin(); it != cache_.end() && dropped < 1000;) {
            it = cache_.erase(it);
            ++dropped;
        }
    }

    int ttl = result.ttl > 0 ? result.ttl : 30;
    if (!result.address) ttl = 5;

    cache_[domain] = CacheEntry{
        result.address,
        NowMs() + ttl * 1000LL,
        !result.address.has_value()
    };
}
