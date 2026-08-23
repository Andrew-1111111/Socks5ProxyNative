#pragma once

#include "../config/ProxyConfiguration.h"

#include <string>
#include <unordered_map>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

class FriendlyNameResolver {
public:
    explicit FriendlyNameResolver(const std::vector<IPAddressMapping>& mappings);

    std::string FriendlySuffix(const std::string& ip) const;
    std::string FriendlySuffix(const sockaddr* addr) const;

private:
    std::unordered_map<std::string, std::string> map_;
};
