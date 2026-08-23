#pragma once

#include <cstdint>

namespace socks5 {

constexpr uint8_t kVersion = 0x05;
constexpr uint8_t kReserved = 0x00;

namespace AddressType {
constexpr uint8_t IPv4 = 0x01;
constexpr uint8_t DomainName = 0x03;
constexpr uint8_t IPv6 = 0x04;
}

namespace Command {
constexpr uint8_t Connect = 0x01;
constexpr uint8_t Bind = 0x02;
constexpr uint8_t UdpAssociate = 0x03;
}

namespace ReplyCode {
constexpr uint8_t Succeeded = 0x00;
constexpr uint8_t GeneralFailure = 0x01;
constexpr uint8_t ConnectionNotAllowed = 0x02;
constexpr uint8_t NetworkUnreachable = 0x03;
constexpr uint8_t HostUnreachable = 0x04;
constexpr uint8_t ConnectionRefused = 0x05;
constexpr uint8_t TtlExpired = 0x06;
constexpr uint8_t CommandNotSupported = 0x07;
constexpr uint8_t AddressTypeNotSupported = 0x08;
}

namespace AuthMethod {
constexpr uint8_t NoAuth = 0x00;
constexpr uint8_t Gssapi = 0x01;
constexpr uint8_t UsernamePassword = 0x02;
constexpr uint8_t NoAcceptableMethods = 0xFF;
}

namespace AuthProtocol {
constexpr uint8_t Version = 0x01;
constexpr uint8_t Success = 0x00;
constexpr uint8_t Failure = 0x01;
}

namespace Gssapi {
constexpr uint8_t Version = 0x01;
constexpr uint8_t MsgAuth = 0x01;
constexpr uint8_t MsgProtection = 0x02;
constexpr uint8_t MsgEncapsulated = 0x03;
constexpr uint8_t MsgAbort = 0xFF;
constexpr uint8_t ProtectIntegrity = 0x01;
constexpr uint8_t ProtectConfidentiality = 0x02;
constexpr uint8_t ProtectSelective = 0x03;
}

namespace UdpFrag {
constexpr uint8_t Standalone = 0x00;
constexpr uint8_t NumberMask = 0x7F;
constexpr uint8_t LastFlag = 0x80;
}

}  // namespace socks5
