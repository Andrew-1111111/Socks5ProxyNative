#pragma once

#include "../config/ProxyConfiguration.h"

#include <string>
#include <unordered_map>
#include <vector>

struct sockaddr;

class FriendlyNameResolver {
public:
    explicit FriendlyNameResolver(const std::vector<IPAddressMapping>& mappings);

    std::string FriendlySuffix(const std::string& ip) const;
    std::string FriendlySuffix(const sockaddr* addr) const;

private:
    std::unordered_map<std::string, std::string> map_;
};
