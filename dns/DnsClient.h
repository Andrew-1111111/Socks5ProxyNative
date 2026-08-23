#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

/// DNS wire format helpers + shared response cache (I/O is in DnsResolver).
class DnsClient {
public:
    struct DnsResult {
        std::optional<std::string> address;
        int ttl = 30;
        bool truncated = false;
        /// False for timeouts/I/O/parse failures — must not be cached.
        bool fromNetwork = false;
        static DnsResult Invalid() { return {}; }
    };

    explicit DnsClient(const std::string& dnsServer);

    const std::string& Server() const { return dnsServer_; }

    /// Non-blocking cache lookup (including negative cache).
    std::optional<std::optional<std::string>> TryGetCached(const std::string& domain);
    void Cache(const std::string& domain, const DnsResult& result);

    static std::vector<uint8_t> BuildQuery(const std::string& domain, uint16_t id, uint16_t type);
    static DnsResult ParseResponse(const uint8_t* buffer, int length, uint16_t expectedId, uint16_t expectedType);
    static int SkipName(const uint8_t* buffer, int length, int pos);
    static uint16_t GenerateId();

private:
    struct CacheEntry {
        std::optional<std::string> address;
        long long expiryMs = 0;
        bool negative = false;
    };

    std::string dnsServer_;
    std::mutex cacheMutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
};
