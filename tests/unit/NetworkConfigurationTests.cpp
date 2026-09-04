#include "../TestFramework.h"

#include "../../config/NetworkConfiguration.h"
#include "../../network/Network.h"

#include <cstring>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

namespace {

struct NetworkConfigSnapshot {
    std::string listenIp = NetworkConfiguration::ListenIPAddress;
    uint16_t listenPort = NetworkConfiguration::ListenPort;
    std::string outputIp = NetworkConfiguration::OutputInterfaceIP;
    int outputFamily = NetworkConfiguration::OutputAddressFamily;
    std::string dns = NetworkConfiguration::DnsServer;
    int maxConn = NetworkConfiguration::MaxConnections;
    std::string user = NetworkConfiguration::Username;
    std::string pass = NetworkConfiguration::Password;
    int idle = NetworkConfiguration::IdleTimeoutMs;
    int connect = NetworkConfiguration::ConnectTimeoutMs;
    int sendBuf = NetworkConfiguration::SendBufferSize;
    int recvBuf = NetworkConfiguration::ReceiveBufferSize;
    int buf = NetworkConfiguration::BufferSize;
    bool noDelay = NetworkConfiguration::NoDelay;
    bool keepAlive = NetworkConfiguration::KeepAlive;

    ~NetworkConfigSnapshot() {
        NetworkConfiguration::ListenIPAddress = listenIp;
        NetworkConfiguration::ListenPort = listenPort;
        NetworkConfiguration::OutputInterfaceIP = outputIp;
        NetworkConfiguration::OutputAddressFamily = outputFamily;
        NetworkConfiguration::DnsServer = dns;
        NetworkConfiguration::MaxConnections = maxConn;
        NetworkConfiguration::Username = user;
        NetworkConfiguration::Password = pass;
        NetworkConfiguration::IdleTimeoutMs = idle;
        NetworkConfiguration::ConnectTimeoutMs = connect;
        NetworkConfiguration::SendBufferSize = sendBuf;
        NetworkConfiguration::ReceiveBufferSize = recvBuf;
        NetworkConfiguration::BufferSize = buf;
        NetworkConfiguration::NoDelay = noDelay;
        NetworkConfiguration::KeepAlive = keepAlive;
    }
};

}  // namespace

TEST(NetworkConfiguration, SetMaxConnectionsBounds) {
    NetworkConfigSnapshot guard;
    std::string error;
    EXPECT_TRUE(NetworkConfiguration::SetMaxConnections(0, error));
    EXPECT_EQ(NetworkConfiguration::MaxConnections, 0);
    EXPECT_TRUE(NetworkConfiguration::SetMaxConnections(1048576, error));
    EXPECT_FALSE(NetworkConfiguration::SetMaxConnections(-1, error));
    EXPECT_TRUE(error.find("0-1048576") != std::string::npos);
    EXPECT_FALSE(NetworkConfiguration::SetMaxConnections(1048577, error));
}

TEST(NetworkConfiguration, SetUsernamePasswordValidation) {
    NetworkConfigSnapshot guard;
    std::string error;
    EXPECT_FALSE(NetworkConfiguration::SetUsernamePassword("", "x", error));
    EXPECT_FALSE(NetworkConfiguration::SetUsernamePassword("x", "", error));
    EXPECT_TRUE(NetworkConfiguration::SetUsernamePassword("alice", "secret", error));
    EXPECT_TRUE(NetworkConfiguration::HasCredentials());
    EXPECT_EQ(NetworkConfiguration::Username, "alice");
    EXPECT_EQ(NetworkConfiguration::Password, "secret");

    EXPECT_FALSE(NetworkConfiguration::SetUsernamePassword(std::string(256, 'a'), "b", error));
    EXPECT_TRUE(error.find("255") != std::string::npos);
}

TEST(NetworkConfiguration, HasCredentialsRequiresBoth) {
    NetworkConfigSnapshot guard;
    NetworkConfiguration::Username = "u";
    NetworkConfiguration::Password = "";
    EXPECT_FALSE(NetworkConfiguration::HasCredentials());
    NetworkConfiguration::Password = "p";
    EXPECT_TRUE(NetworkConfiguration::HasCredentials());
}

TEST(NetworkConfiguration, SetSocketOptionsAppliesAndRejects) {
    NetworkConfigSnapshot guard;
    std::string error;
    EXPECT_TRUE(NetworkConfiguration::SetSocketOptions(
        1000, 2000, 3000, 4000, 5000, 6000, 7000,
        8192, 8192, 4096,
        1, 0, 1, 10,
        60, 10, 5,
        error));
    EXPECT_EQ(NetworkConfiguration::IdleTimeoutMs, 1000);
    EXPECT_EQ(NetworkConfiguration::ConnectTimeoutMs, 2000);
    EXPECT_EQ(NetworkConfiguration::SendBufferSize, 8192);
    EXPECT_TRUE(NetworkConfiguration::NoDelay);
    EXPECT_FALSE(NetworkConfiguration::KeepAlive);
    EXPECT_TRUE(NetworkConfiguration::LingerEnabled);
    EXPECT_EQ(NetworkConfiguration::LingerTimeoutSec, 10);

    EXPECT_FALSE(NetworkConfiguration::SetSocketOptions(
        -1, -1, -1, -1, -1, -1, -1,
        -1, -1, 16 * 1024 * 1024 + 1,
        -1, -1, -1, -1,
        -1, -1, -1,
        error));
    EXPECT_TRUE(error.find("BufferSize") != std::string::npos);
}

TEST(NetworkConfiguration, SetSocketOptionsRejectsZeroConnectTimeout) {
    NetworkConfigSnapshot guard;
    std::string error;
    EXPECT_FALSE(NetworkConfiguration::SetSocketOptions(
        -1, 0, -1, -1, -1, -1, -1,
        -1, -1, -1,
        -1, -1, -1, -1,
        -1, -1, -1,
        error));
    EXPECT_TRUE(error.find("ConnectTimeoutMs") != std::string::npos);
}

TEST(NetworkConfiguration, SetServerInterfaceLoopback) {
    NetworkConfigSnapshot guard;
    std::string error;
    EXPECT_TRUE(NetworkConfiguration::SetServerInterfaceIP("127.0.0.1", 0, error));
    EXPECT_EQ(NetworkConfiguration::ListenIPAddress, "127.0.0.1");
    EXPECT_EQ(NetworkConfiguration::ListenPort, 0);

    EXPECT_FALSE(NetworkConfiguration::SetServerInterfaceIP("not-an-ip", 1080, error));
    EXPECT_FALSE(NetworkConfiguration::SetServerInterfaceIP("", 1080, error));
    EXPECT_FALSE(NetworkConfiguration::SetServerInterfaceIP("127.0.0.1", -1, error));
    EXPECT_FALSE(NetworkConfiguration::SetServerInterfaceIP("127.0.0.1", 70000, error));
}

TEST(NetworkConfiguration, FillListenAddressIpv4) {
    NetworkConfigSnapshot guard;
    NetworkConfiguration::ListenIPAddress = "127.0.0.1";
    NetworkConfiguration::ListenPort = 1080;
    sockaddr_storage storage{};
    int length = 0;
    EXPECT_TRUE(NetworkConfiguration::FillListenAddress(storage, length));
    EXPECT_EQ(length, static_cast<int>(sizeof(sockaddr_in)));
    EXPECT_EQ(storage.ss_family, AF_INET);
    const auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
    EXPECT_EQ(ntohs(v4->sin_port), 1080);
}

TEST(NetworkConfiguration, FillListenAddressIpv6) {
    NetworkConfigSnapshot guard;
    NetworkConfiguration::ListenIPAddress = "::1";
    NetworkConfiguration::ListenPort = 1080;
    sockaddr_storage storage{};
    int length = 0;
    EXPECT_TRUE(NetworkConfiguration::FillListenAddress(storage, length));
    EXPECT_EQ(length, static_cast<int>(sizeof(sockaddr_in6)));
    EXPECT_EQ(storage.ss_family, AF_INET6);
}

TEST(NetworkConfiguration, FillOutputAndDnsEndpoints) {
    NetworkConfigSnapshot guard;
    NetworkConfiguration::OutputInterfaceIP = "127.0.0.1";
    sockaddr_storage storage{};
    int length = 0;
    EXPECT_TRUE(NetworkConfiguration::FillOutputBindAddress(storage, length, 53));
    EXPECT_EQ(ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port), 53);

    NetworkConfiguration::DnsServer = "8.8.8.8";
    EXPECT_TRUE(NetworkConfiguration::FillDnsEndpoint(storage, length));
    EXPECT_EQ(NetworkUtils::IPToString(reinterpret_cast<sockaddr*>(&storage)), "8.8.8.8");
    EXPECT_EQ(ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port), 53);
}

TEST(NetworkConfiguration, SetOutputInterfaceIpLoopback) {
    NetworkConfigSnapshot guard;
    std::string error;
    EXPECT_TRUE(NetworkConfiguration::SetOutputInterfaceIP("127.0.0.1", error));
    EXPECT_EQ(NetworkConfiguration::OutputInterfaceIP, "127.0.0.1");
    EXPECT_EQ(NetworkConfiguration::OutputAddressFamily, AF_INET);
    EXPECT_FALSE(NetworkConfiguration::OutputIPv6Available);
}
