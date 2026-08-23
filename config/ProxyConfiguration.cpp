#include "ProxyConfiguration.h"
#include "NetworkConfiguration.h"

#include <cctype>
#include <chrono>
#include <fstream>
#include <sstream>
#include <thread>

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
    value = std::stoi(json.substr(pos, end - pos));
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
    ExtractInt(json, "ListenPort", config.ListenPort);
    ExtractStringArray(json, "OutputIPAddress", config.OutputIPAddress);
    ExtractStringArray(json, "OutputInterfaceName", config.OutputInterfaceName);
    ExtractString(json, "DnsServer", config.DnsServer);
    ExtractInt(json, "MaxConnections", config.MaxConnections);
    ExtractInt(json, "RunDelayS", config.RunDelayS);
    ExtractString(json, "Username", config.Username);
    ExtractString(json, "Password", config.Password);
    ExtractBoolAsInt(json, "EnableGssapi", config.EnableGssapi);
    ExtractInt(json, "GssapiMaxProtection", config.GssapiMaxProtection);
    ExtractMappings(json, config.IPAddressMappings);

    ExtractInt(json, "IdleTimeoutMs", config.IdleTimeoutMs);
    ExtractInt(json, "ConnectTimeoutMs", config.ConnectTimeoutMs);
    ExtractInt(json, "SendTimeoutMs", config.SendTimeoutMs);
    ExtractInt(json, "ReceiveTimeoutMs", config.ReceiveTimeoutMs);
    ExtractInt(json, "DnsSendTimeoutMs", config.DnsSendTimeoutMs);
    ExtractInt(json, "DnsReceiveTimeoutMs", config.DnsReceiveTimeoutMs);
    ExtractInt(json, "UdpAssociateIdleTimeoutMs", config.UdpAssociateIdleTimeoutMs);
    ExtractInt(json, "SendBufferSize", config.SendBufferSize);
    ExtractInt(json, "ReceiveBufferSize", config.ReceiveBufferSize);
    ExtractInt(json, "BufferSize", config.BufferSize);
    ExtractBoolAsInt(json, "NoDelay", config.NoDelay);
    ExtractBoolAsInt(json, "KeepAlive", config.KeepAlive);
    ExtractBoolAsInt(json, "LingerEnabled", config.LingerEnabled);
    ExtractInt(json, "LingerTimeoutSec", config.LingerTimeoutSec);
    ExtractInt(json, "TcpKeepAliveTime", config.TcpKeepAliveTime);
    ExtractInt(json, "TcpKeepAliveInterval", config.TcpKeepAliveInterval);
    ExtractInt(json, "TcpKeepAliveRetryCount", config.TcpKeepAliveRetryCount);

    config.ListenIPAddress = Trim(config.ListenIPAddress);
    config.DnsServer = Trim(config.DnsServer);
    config.Username = Trim(config.Username);
    config.Password = Trim(config.Password);
    return true;
}

bool ProxyConfiguration::IsValid(std::string& errorMessage) const {
    if (RunDelayS > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(RunDelayS));
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

    if (!NetworkConfiguration::SetSocketOptions(
            IdleTimeoutMs, ConnectTimeoutMs, SendTimeoutMs, ReceiveTimeoutMs,
            DnsSendTimeoutMs, DnsReceiveTimeoutMs, UdpAssociateIdleTimeoutMs,
            SendBufferSize, ReceiveBufferSize, BufferSize,
            NoDelay, KeepAlive, LingerEnabled, LingerTimeoutSec,
            TcpKeepAliveTime, TcpKeepAliveInterval, TcpKeepAliveRetryCount,
            errorMessage)) {
        return false;
    }

    return true;
}
