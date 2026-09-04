#include "../TestFramework.h"

#include "../../server/protocol/Socks5Constants.h"

TEST(Socks5Constants, VersionAndCommands) {
    EXPECT_EQ(socks5::kVersion, 0x05);
    EXPECT_EQ(socks5::kReserved, 0x00);
    EXPECT_EQ(socks5::Command::Connect, 0x01);
    EXPECT_EQ(socks5::Command::Bind, 0x02);
    EXPECT_EQ(socks5::Command::UdpAssociate, 0x03);
}

TEST(Socks5Constants, AddressTypesAndAuth) {
    EXPECT_EQ(socks5::AddressType::IPv4, 0x01);
    EXPECT_EQ(socks5::AddressType::DomainName, 0x03);
    EXPECT_EQ(socks5::AddressType::IPv6, 0x04);
    EXPECT_EQ(socks5::AuthMethod::NoAuth, 0x00);
    EXPECT_EQ(socks5::AuthMethod::Gssapi, 0x01);
    EXPECT_EQ(socks5::AuthMethod::UsernamePassword, 0x02);
    EXPECT_EQ(socks5::AuthMethod::NoAcceptableMethods, 0xFF);
}

TEST(Socks5Constants, ReplyCodesAndUdpFrag) {
    EXPECT_EQ(socks5::ReplyCode::Succeeded, 0x00);
    EXPECT_EQ(socks5::ReplyCode::CommandNotSupported, 0x07);
    EXPECT_EQ(socks5::UdpFrag::Standalone, 0x00);
    EXPECT_EQ(socks5::UdpFrag::LastFlag, 0x80);
    EXPECT_EQ(socks5::UdpFrag::NumberMask, 0x7F);
}

TEST(Socks5Constants, AuthProtocolAndGssapi) {
    EXPECT_EQ(socks5::AuthProtocol::Version, 0x01);
    EXPECT_EQ(socks5::AuthProtocol::Success, 0x00);
    EXPECT_EQ(socks5::AuthProtocol::Failure, 0x01);
    EXPECT_EQ(socks5::Gssapi::Version, 0x01);
    EXPECT_EQ(socks5::Gssapi::MsgAuth, 0x01);
    EXPECT_EQ(socks5::Gssapi::MsgProtection, 0x02);
    EXPECT_EQ(socks5::Gssapi::MsgEncapsulated, 0x03);
    EXPECT_EQ(socks5::Gssapi::MsgAbort, 0xFF);
    EXPECT_EQ(socks5::Gssapi::ProtectIntegrity, 0x01);
    EXPECT_EQ(socks5::Gssapi::ProtectConfidentiality, 0x02);
    EXPECT_EQ(socks5::Gssapi::ProtectSelective, 0x03);
}

TEST(Socks5Constants, AllReplyCodesDefined) {
    EXPECT_EQ(socks5::ReplyCode::GeneralFailure, 0x01);
    EXPECT_EQ(socks5::ReplyCode::ConnectionNotAllowed, 0x02);
    EXPECT_EQ(socks5::ReplyCode::NetworkUnreachable, 0x03);
    EXPECT_EQ(socks5::ReplyCode::HostUnreachable, 0x04);
    EXPECT_EQ(socks5::ReplyCode::ConnectionRefused, 0x05);
    EXPECT_EQ(socks5::ReplyCode::TtlExpired, 0x06);
    EXPECT_EQ(socks5::ReplyCode::AddressTypeNotSupported, 0x08);
}
