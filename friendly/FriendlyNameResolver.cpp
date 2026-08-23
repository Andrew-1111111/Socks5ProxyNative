#include "FriendlyNameResolver.h"

#include "../network/Network.h"
#include "../utils/Logger.h"

FriendlyNameResolver::FriendlyNameResolver(const std::vector<IPAddressMapping>& mappings) {
    int invalid = 0;
    int duplicates = 0;

    for (const auto& m : mappings) {
        std::string ipStr = m.IPAddress;
        std::string name = m.FriendlyName;
        while (!ipStr.empty() && (ipStr.front() == ' ' || ipStr.front() == '\t')) ipStr.erase(ipStr.begin());
        while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) name.erase(name.begin());
        while (!ipStr.empty() && (ipStr.back() == ' ' || ipStr.back() == '\t')) ipStr.pop_back();
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();

        if (ipStr.empty() || name.empty()) {
            ++invalid;
            continue;
        }

        sockaddr_storage storage{};
        int family = 0;
        if (!NetworkUtils::ParseIP(ipStr, storage, family)) {
            ++invalid;
            continue;
        }

        const std::string key = NetworkUtils::IPToString(reinterpret_cast<sockaddr*>(&storage));
        if (map_.count(key)) {
            ++duplicates;
        }
        map_[key] = name;
    }

    if (invalid > 0) {
        Logger::Instance().Warning("Some IPAddressMappings are invalid and were ignored.");
    }
    if (duplicates > 0) {
        Logger::Instance().Warning("Duplicate IPAddressMappings detected (last wins).");
    }
    Logger::Instance().Info("Loaded {Count} IP address mappings for friendly log names",
                            static_cast<int>(map_.size()));
}

std::string FriendlyNameResolver::FriendlySuffix(const std::string& ip) const {
    auto it = map_.find(ip);
    if (it == map_.end()) return {};
    return " (" + it->second + ")";
}

std::string FriendlyNameResolver::FriendlySuffix(const sockaddr* addr) const {
    if (!addr) return {};
    return FriendlySuffix(NetworkUtils::IPToString(addr));
}
