#include "../TestFramework.h"

#include "../../config/ProxyConfiguration.h"

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace {

class TempJsonFile {
public:
    explicit TempJsonFile(const std::string& contents) {
        path_ = fs::temp_directory_path() / ("socks5proxy_test_" + std::to_string(std::hash<std::string>{}(contents)) + ".json");
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        out << contents;
    }

    ~TempJsonFile() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

    std::string path() const { return path_.string(); }

private:
    fs::path path_;
};

}  // namespace

TEST(ProxyConfiguration, LoadMinimalConfig) {
    TempJsonFile file(R"({
  "ListenIPAddress": "127.0.0.1",
  "ListenPort": 1080,
  "OutputIPAddress": [],
  "OutputInterfaceName": [],
  "DnsServer": "8.8.8.8",
  "MaxConnections": 100,
  "RunDelayS": 0,
  "Username": "",
  "Password": "",
  "EnableGssapi": false,
  "GssapiMaxProtection": 1,
  "IPAddressMappings": []
})");

    ProxyConfiguration cfg;
    std::string error;
    EXPECT_TRUE(ProxyConfiguration::LoadFromFile(file.path(), cfg, error));
    EXPECT_EQ(cfg.ListenIPAddress, "127.0.0.1");
    EXPECT_EQ(cfg.ListenPort, 1080);
    EXPECT_EQ(cfg.DnsServer, "8.8.8.8");
    EXPECT_EQ(cfg.MaxConnections, 100);
    EXPECT_EQ(cfg.EnableGssapi, 0);
    EXPECT_TRUE(cfg.IPAddressMappings.empty());
}

TEST(ProxyConfiguration, LoadMappingsAndCredentials) {
    TempJsonFile file(R"({
  "ListenIPAddress": "0.0.0.0",
  "ListenPort": 1081,
  "OutputIPAddress": ["10.0.0.1"],
  "OutputInterfaceName": ["tap1"],
  "DnsServer": "1.1.1.1",
  "MaxConnections": 0,
  "RunDelayS": 5,
  "Username": "user",
  "Password": "pass",
  "EnableGssapi": true,
  "GssapiMaxProtection": 2,
  "IPAddressMappings": [
    { "IPAddress": "192.168.0.10", "FriendlyName": "PC_1" },
    { "IPAddress": "192.168.0.11", "FriendlyName": "PC_2" }
  ]
})");

    ProxyConfiguration cfg;
    std::string error;
    EXPECT_TRUE(ProxyConfiguration::LoadFromFile(file.path(), cfg, error));
    EXPECT_EQ(cfg.Username, "user");
    EXPECT_EQ(cfg.Password, "pass");
    EXPECT_EQ(cfg.EnableGssapi, 1);
    EXPECT_EQ(cfg.GssapiMaxProtection, 2);
    EXPECT_EQ(cfg.OutputIPAddress.size(), 1u);
    EXPECT_EQ(cfg.OutputIPAddress[0], "10.0.0.1");
    EXPECT_EQ(cfg.OutputInterfaceName.size(), 1u);
    EXPECT_EQ(cfg.IPAddressMappings.size(), 2u);
    EXPECT_EQ(cfg.IPAddressMappings[0].FriendlyName, "PC_1");
}

TEST(ProxyConfiguration, MissingFileFails) {
    ProxyConfiguration cfg;
    std::string error;
    EXPECT_FALSE(ProxyConfiguration::LoadFromFile("Z:\\does\\not\\exist\\proxy.json", cfg, error));
    EXPECT_FALSE(error.empty());
}

TEST(ProxyConfiguration, MissingListenAddressFails) {
    TempJsonFile file(R"({ "ListenPort": 1080 })");
    ProxyConfiguration cfg;
    std::string error;
    EXPECT_FALSE(ProxyConfiguration::LoadFromFile(file.path(), cfg, error));
    EXPECT_TRUE(error.find("ListenIPAddress") != std::string::npos);
}

TEST(ProxyConfiguration, IsValidRejectsMismatchedCredentials) {
    ProxyConfiguration cfg;
    cfg.ListenIPAddress = "127.0.0.1";
    cfg.ListenPort = 1080;
    cfg.Username = "only-user";
    cfg.Password = "";
    cfg.RunDelayS = 0;
    std::string error;
    EXPECT_FALSE(cfg.IsValid(error));
    EXPECT_TRUE(error.find("Username and Password") != std::string::npos);
}

TEST(ProxyConfiguration, IsValidRejectsBadRunDelay) {
    ProxyConfiguration cfg;
    cfg.ListenIPAddress = "127.0.0.1";
    cfg.ListenPort = 1080;
    cfg.RunDelayS = -1;
    std::string error;
    EXPECT_FALSE(cfg.IsValid(error));
    EXPECT_TRUE(error.find("RunDelayS") != std::string::npos);
}

TEST(ProxyConfiguration, LoadSocketOptionsAndEscapes) {
    TempJsonFile file(R"({
  "ListenIPAddress": "127.0.0.1",
  "ListenPort": 2080,
  "OutputIPAddress": [],
  "OutputInterfaceName": [],
  "DnsServer": "8.8.8.8",
  "MaxConnections": 10,
  "RunDelayS": 0,
  "Username": "u\"ser",
  "Password": "p\\ass",
  "EnableGssapi": 1,
  "GssapiMaxProtection": 3,
  "IdleTimeoutMs": 1000,
  "ConnectTimeoutMs": 2000,
  "SendTimeoutMs": 3000,
  "ReceiveTimeoutMs": 4000,
  "DnsSendTimeoutMs": 1500,
  "DnsReceiveTimeoutMs": 1600,
  "UdpAssociateIdleTimeoutMs": 1700,
  "SendBufferSize": 4096,
  "ReceiveBufferSize": 8192,
  "BufferSize": 2048,
  "NoDelay": false,
  "KeepAlive": true,
  "LingerEnabled": true,
  "LingerTimeoutSec": 3,
  "TcpKeepAliveTime": 30,
  "TcpKeepAliveInterval": 5,
  "TcpKeepAliveRetryCount": 3,
  "IPAddressMappings": []
})");

    ProxyConfiguration cfg;
    std::string error;
    EXPECT_TRUE(ProxyConfiguration::LoadFromFile(file.path(), cfg, error));
    EXPECT_EQ(cfg.ListenPort, 2080);
    EXPECT_EQ(cfg.Username, "u\"ser");
    EXPECT_EQ(cfg.Password, "p\\ass");
    EXPECT_EQ(cfg.EnableGssapi, 1);
    EXPECT_EQ(cfg.GssapiMaxProtection, 3);
    EXPECT_EQ(cfg.IdleTimeoutMs, 1000);
    EXPECT_EQ(cfg.BufferSize, 2048);
    EXPECT_EQ(cfg.NoDelay, 0);
    EXPECT_EQ(cfg.KeepAlive, 1);
    EXPECT_EQ(cfg.LingerEnabled, 1);
}

TEST(ProxyConfiguration, InvalidIntegerFails) {
    TempJsonFile file(R"({
  "ListenIPAddress": "127.0.0.1",
  "ListenPort": "oops"
})");
    ProxyConfiguration cfg;
    std::string error;
    EXPECT_FALSE(ProxyConfiguration::LoadFromFile(file.path(), cfg, error));
    EXPECT_TRUE(error.find("ListenPort") != std::string::npos);
}

TEST(ProxyConfiguration, IsValidRejectsBadGssapiProtection) {
    ProxyConfiguration cfg;
    cfg.ListenIPAddress = "127.0.0.1";
    cfg.ListenPort = 1080;
    cfg.RunDelayS = 0;
    cfg.GssapiMaxProtection = 9;
    std::string error;
    EXPECT_FALSE(cfg.IsValid(error));
    EXPECT_TRUE(error.find("GssapiMaxProtection") != std::string::npos);
}

TEST(ProxyConfiguration, IsValidAcceptsLoopbackWithoutOutput) {
    ProxyConfiguration cfg;
    cfg.ListenIPAddress = "127.0.0.1";
    cfg.ListenPort = 0;
    cfg.RunDelayS = 0;
    cfg.DnsServer.clear();
    cfg.OutputIPAddress.clear();
    cfg.OutputInterfaceName.clear();
    std::string error;
    EXPECT_TRUE(cfg.IsValid(error));
}

TEST(ProxyConfiguration, IsValidRejectsHugeRunDelay) {
    ProxyConfiguration cfg;
    cfg.ListenIPAddress = "127.0.0.1";
    cfg.ListenPort = 1080;
    cfg.RunDelayS = 86'401;
    std::string error;
    EXPECT_FALSE(cfg.IsValid(error));
}
