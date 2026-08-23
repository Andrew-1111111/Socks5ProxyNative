#include "ProxyConfiguration.h"
#include "NetworkConfiguration.h"

#include <cctype>
#include <exception>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

std::string Trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

std::string UnescapeJsonString(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            ++i;
            switch (s[i]) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case 'n': out.push_back('\n'); break;
            case 't': out.push_back('\t'); break;
            case '/': out.push_back('/'); break;
            default: out.push_back(s[i]); break;
            }
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

bool ExtractString(const std::string& json, const std::string& key, std::string& value) {
    const std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size()) return false;

    if (json.compare(pos, 4, "null") == 0) {
        value.clear();
        return true;
    }
    if (json[pos] != '"') return false;
    ++pos;
    std::string raw;
    while (pos < json.size()) {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            raw.push_back(json[pos++]);
            raw.push_back(json[pos++]);
            continue;
        }
        if (json[pos] == '"') break;
        raw.push_back(json[pos++]);
    }
    if (pos >= json.size() || json[pos] != '"') return false;
    value = UnescapeJsonString(raw);
    return true;
}

bool ExtractInt(const std::string& json, const std::string& key, int& value) {
    const std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size()) return false;
    if (json.compare(pos, 4, "null") == 0) return true;

    size_t end = pos;
    if (json[end] == '-') ++end;
    while (end < json.size() && std::isdigit(static_cast<unsigned char>(json[end]))) ++end;
    if (end == pos || (end == pos + 1 && json[pos] == '-')) return false;
    try {
        value = std::stoi(json.substr(pos, end - pos));
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

/// true/false or 0/1 → out as 0/1. Returns false if key missing.
bool ExtractBoolAsInt(const std::string& json, const std::string& key, int& value) {
    const std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size()) return false;
    if (json.compare(pos, 4, "true") == 0) {
        value = 1;
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        value = 0;
        return true;
    }
    int n = 0;
    if (!ExtractInt(json, key, n)) return false;
    value = n != 0 ? 1 : 0;
    return true;
}

bool ExtractStringArray(const std::string& json, const std::string& key, std::vector<std::string>& values) {
    values.clear();
    const std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size()) return false;
    if (json.compare(pos, 4, "null") == 0) return true;
    if (json[pos] != '[') return false;
    ++pos;

    while (pos < json.size()) {
        while (pos < json.size() && (std::isspace(static_cast<unsigned char>(json[pos])) || json[pos] == ',')) ++pos;
        if (pos >= json.size()) break;
        if (json[pos] == ']') break;
        if (json.compare(pos, 4, "null") == 0) {
            pos += 4;
            continue;
        }
        if (json[pos] != '"') return false;
        ++pos;
        std::string raw;
        while (pos < json.size()) {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                raw.push_back(json[pos++]);
                raw.push_back(json[pos++]);
                continue;
            }
            if (json[pos] == '"') break;
            raw.push_back(json[pos++]);
        }
        if (pos >= json.size() || json[pos] != '"') return false;
        ++pos;
        values.push_back(UnescapeJsonString(raw));
    }
    return true;
}

bool ExtractMappings(const std::string& json, std::vector<IPAddressMapping>& mappings) {
    mappings.clear();
    const std::string pattern = "\"IPAddressMappings\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return true;
    pos = json.find('[', pos);
    if (pos == std::string::npos) return false;
    ++pos;

    while (pos < json.size()) {
        while (pos < json.size() && json[pos] != '{' && json[pos] != ']') ++pos;
        if (pos >= json.size() || json[pos] == ']') break;
        size_t end = json.find('}', pos);
        if (end == std::string::npos) return false;
        const std::string object = json.substr(pos, end - pos + 1);
        IPAddressMapping mapping;
        ExtractString(object, "IPAddress", mapping.IPAddress);
        ExtractString(object, "FriendlyName", mapping.FriendlyName);
        if (!mapping.IPAddress.empty() || !mapping.FriendlyName.empty()) {
            mappings.push_back(std::move(mapping));
        }
        pos = end + 1;
    }
    return true;
}

}  // namespace

bool ProxyConfiguration::LoadFromFile(const std::string& path, ProxyConfiguration& config, std::string& errorMessage) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        errorMessage = "Proxy configuration file not found: '" + path + "'. "
                       "Please create the configuration file or specify a valid path using --config <path>.";
        return false;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    const std::string json = ss.str();

    if (!ExtractString(json, "ListenIPAddress", config.ListenIPAddress) || config.ListenIPAddress.empty()) {
        errorMessage = "ListenIPAddress is required.";
        return false;
    }
    auto hasKey = [&](const char* key) {
        return json.find("\"" + std::string(key) + "\"") != std::string::npos;
    };
    auto readInt = [&](const char* key, int& value) {
        if (!hasKey(key) || ExtractInt(json, key, value)) return true;
        errorMessage = std::string("Invalid integer value for ") + key + ".";
        return false;
    };
    auto readBool = [&](const char* key, int& value) {
        if (!hasKey(key) || ExtractBoolAsInt(json, key, value)) return true;
        errorMessage = std::string("Invalid boolean value for ") + key + ".";
        return false;
    };
    auto readString = [&](const char* key, std::string& value) {
        if (!hasKey(key) || ExtractString(json, key, value)) return true;
        errorMessage = std::string("Invalid string value for ") + key + ".";
        return false;
    };
    auto readStrings = [&](const char* key, std::vector<std::string>& value) {
        if (!hasKey(key) || ExtractStringArray(json, key, value)) return true;
        errorMessage = std::string("Invalid string array for ") + key + ".";
        return false;
    };

    if (!readInt("ListenPort", config.ListenPort) ||
        !readStrings("OutputIPAddress", config.OutputIPAddress) ||
        !readStrings("OutputInterfaceName", config.OutputInterfaceName) ||
        !readString("DnsServer", config.DnsServer) ||
        !readInt("MaxConnections", config.MaxConnections) ||
        !readInt("RunDelayS", config.RunDelayS) ||
        !readString("Username", config.Username) ||
        !readString("Password", config.Password) ||
        !readBool("EnableGssapi", config.EnableGssapi) ||
        !readInt("GssapiMaxProtection", config.GssapiMaxProtection) ||
        !ExtractMappings(json, config.IPAddressMappings) ||
        !readInt("IdleTimeoutMs", config.IdleTimeoutMs) ||
        !readInt("ConnectTimeoutMs", config.ConnectTimeoutMs) ||
        !readInt("SendTimeoutMs", config.SendTimeoutMs) ||
        !readInt("ReceiveTimeoutMs", config.ReceiveTimeoutMs) ||
        !readInt("DnsSendTimeoutMs", config.DnsSendTimeoutMs) ||
        !readInt("DnsReceiveTimeoutMs", config.DnsReceiveTimeoutMs) ||
        !readInt("UdpAssociateIdleTimeoutMs", config.UdpAssociateIdleTimeoutMs) ||
        !readInt("SendBufferSize", config.SendBufferSize) ||
        !readInt("ReceiveBufferSize", config.ReceiveBufferSize) ||
        !readInt("BufferSize", config.BufferSize) ||
        !readBool("NoDelay", config.NoDelay) ||
        !readBool("KeepAlive", config.KeepAlive) ||
        !readBool("LingerEnabled", config.LingerEnabled) ||
        !readInt("LingerTimeoutSec", config.LingerTimeoutSec) ||
        !readInt("TcpKeepAliveTime", config.TcpKeepAliveTime) ||
        !readInt("TcpKeepAliveInterval", config.TcpKeepAliveInterval) ||
        !readInt("TcpKeepAliveRetryCount", config.TcpKeepAliveRetryCount)) {
        if (errorMessage.empty()) {
            errorMessage = "Invalid IPAddressMappings value.";
        }
        return false;
    }

    config.ListenIPAddress = Trim(config.ListenIPAddress);
    config.DnsServer = Trim(config.DnsServer);
    config.Username = Trim(config.Username);
    config.Password = Trim(config.Password);
    return true;
}

bool ProxyConfiguration::IsValid(std::string& errorMessage) const {
    if (RunDelayS < 0 || RunDelayS > 86'400) {
        errorMessage = "RunDelayS must be in the range 0-86400.";
        return false;
    }

    const bool hasUsername = !Username.empty();
    const bool hasPassword = !Password.empty();
    if (hasUsername != hasPassword) {
        errorMessage = "Username and Password must either both be set or both be empty.";
        return false;
    }

    if (!NetworkConfiguration::SetServerInterfaceIP(ListenIPAddress, ListenPort, errorMessage)) {
        return false;
    }

    if (!OutputIPAddress.empty()) {
        bool success = false;
        for (const auto& addr : OutputIPAddress) {
            if (!addr.empty() && NetworkConfiguration::SetOutputInterfaceIP(addr, errorMessage)) {
                success = true;
                break;
            }
        }
        if (!success) return false;
    }

    if (!OutputInterfaceName.empty()) {
        bool success = false;
        std::string accumulated;
        for (const auto& ifaceName : OutputInterfaceName) {
            std::string tempError;
            if (!ifaceName.empty() && NetworkConfiguration::SetOutputInterfaceName(ifaceName, tempError)) {
                success = true;
                break;
            }
            if (!tempError.empty()) {
                if (!accumulated.empty()) accumulated += "\n";
                accumulated += tempError;
            }
        }
        if (!success) {
            errorMessage = accumulated.empty() ? "No valid output interface found." : accumulated;
            return false;
        }
    }

    if (!NetworkConfiguration::SetSocketOptions(
            IdleTimeoutMs, ConnectTimeoutMs, SendTimeoutMs, ReceiveTimeoutMs,
            DnsSendTimeoutMs, DnsReceiveTimeoutMs, UdpAssociateIdleTimeoutMs,
            SendBufferSize, ReceiveBufferSize, BufferSize,
            NoDelay, KeepAlive, LingerEnabled, LingerTimeoutSec,
            TcpKeepAliveTime, TcpKeepAliveInterval, TcpKeepAliveRetryCount,
            errorMessage)) {
        return false;
    }

    if (!DnsServer.empty()) {
        if (!NetworkConfiguration::SetDnsIP(DnsServer, errorMessage)) {
            return false;
        }
    }

    if (!NetworkConfiguration::SetMaxConnections(MaxConnections, errorMessage)) {
        return false;
    }

    if (!Username.empty() && !Password.empty()) {
        if (!NetworkConfiguration::SetUsernamePassword(Username, Password, errorMessage)) {
            return false;
        }
    }

    if (EnableGssapi >= 0) {
        NetworkConfiguration::EnableGssapi = EnableGssapi != 0;
    }
    if (GssapiMaxProtection >= 1 && GssapiMaxProtection <= 3) {
        NetworkConfiguration::GssapiMaxProtection = GssapiMaxProtection;
    } else if (GssapiMaxProtection != -1) {
        errorMessage = "GssapiMaxProtection must be 1 (integrity), 2 (confidentiality), or 3 (selective).";
        return false;
    }

    return true;
}
