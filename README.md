# Socks5Proxy

**English** | [Русский](README.ru.md)

A high-performance SOCKS5 proxy in C++20 (Windows, IOCP) with outbound traffic binding to a chosen interface, built-in DNS resolution, and detailed logging.

## Features

- Full baseline SOCKS5 (RFC 1928) support for `CONNECT` and `UDP ASSOCIATE`.
- Support for `IPv4`, `IPv6`, and domain names.
- Asynchronous IOCP architecture handling many concurrent connections.
- Limit on simultaneous connections (`MaxConnections`); `0` means unlimited.
- Bind outbound TCP/UDP to a specific local IP (`OutputIPAddress`) or interface name (`OutputInterfaceName`).
- Resolve hostnames via a configurable DNS server (`DnsServer`) with caching, EDNS, retries, and TCP fallback.
- UDP relay with client validation, source filtering, and idle timeout.
- Friendly names for IPs in logs (`IPAddressMappings`) for easier troubleshooting.
- Single-instance guard to prevent a second copy from running.
- Clean shutdown on `Ctrl+C` and proper resource cleanup.
- Console logging with configurable levels.

## Protocol support

### Supported

- SOCKS5 version `0x05`
- Authentication method `No Authentication` (`0x00`)
- Authentication method `GSSAPI` (`0x01`, RFC 1961 via Windows SSPI Negotiate)
- Authentication method `Username/Password` (`0x02`)
- Command `CONNECT` (TCP)
- Command `UDP ASSOCIATE` (UDP relay)
- UDP FRAG reassembly (RFC 1928)
- IPv4, IPv6, and domain addresses

### Not supported

- BIND command

## Requirements

- Windows 10/11 (x64)
- Visual Studio 2022+ with C++ desktop workload, **or** CMake 3.16+ with MSVC
- C++20
- Administrator privileges (the app checks this at startup and may relaunch with elevation; elevated rights are needed for binding to ports 1–1024 and firewall rules)

## Quick start

### 1) Build (Visual Studio)

```bash
msbuild Socks5Proxy.sln /p:Configuration=Release /p:Platform=x64
```

Or open `Socks5Proxy.sln` in Visual Studio and build **Release | x64**.

Output: `bin\x64\Release\Socks5Proxy.exe` (with `proxy.json` copied next to it).

### 1b) Build (CMake)

```bash
cmake --preset x64-release
cmake --build --preset x64-release
```

### 2) Configure `proxy.json`

The file lives at the repository root (`proxy.json`) and is copied next to the executable on build.

Example:

```json
{
  "ListenIPAddress": "0.0.0.0",
  "ListenPort": 1080,
  "OutputIPAddress": [],
  "OutputInterfaceName": [
    "tap1",
    "tun2"
  ],
  "DnsServer": "8.8.8.8",
  "MaxConnections": 1000,
  "RunDelayS": 0,
  "Username": "",
  "Password": "",
  "IdleTimeoutMs": 60000,
  "ConnectTimeoutMs": 30000,
  "SendTimeoutMs": 30000,
  "ReceiveTimeoutMs": 30000,
  "DnsSendTimeoutMs": 5000,
  "DnsReceiveTimeoutMs": 5000,
  "UdpAssociateIdleTimeoutMs": 120000,
  "SendBufferSize": 262144,
  "ReceiveBufferSize": 262144,
  "BufferSize": 81920,
  "NoDelay": true,
  "KeepAlive": true,
  "LingerEnabled": false,
  "LingerTimeoutSec": 0,
  "TcpKeepAliveTime": 60,
  "TcpKeepAliveInterval": 10,
  "TcpKeepAliveRetryCount": 5,
  "IPAddressMappings": [
    {
      "IPAddress": "192.168.0.10",
      "FriendlyName": "PC_1"
    }
  ]
}
```

### 3) Run

From the build output directory:

```bash
.\Socks5Proxy.exe
```

Or with an explicit config path:

```bash
.\Socks5Proxy.exe --config "D:\path\to\proxy.json"
```

## Configuration

- `ListenIPAddress` — IP address the SOCKS5 server listens on (e.g. `127.0.0.1` or `0.0.0.0`).
- `ListenPort` — TCP listen port (range: 0–65535). If port 0 is selected, the system will automatically select a random port.
- `OutputIPAddress` — list of local interface IPs for outbound connections. The app picks the first available working address. May be empty.
- `OutputInterfaceName` — list of network interface names for outbound connections. The app picks the first available working interface. Takes precedence over `OutputIPAddress`. May be empty.
- `DnsServer` — DNS server IP for resolving domain names. May be empty (system DNS / limited fallback).
- `MaxConnections` — maximum concurrent connections. `0` means no limit.
- `RunDelayS` — startup delay in seconds. `0` means no delay.
- `IPAddressMappings` — array of IP-to-friendly-name mappings for logging.
- `Username` — SOCKS5 username. Leave unused for `No Authentication`. May be empty.
- `Password` — SOCKS5 password. Leave unused for `No Authentication`. May be empty.
- `EnableGssapi` — offer SOCKS5 GSSAPI (`0x01`) via Windows Negotiate/Kerberos/NTLM. Default `false`.
- `GssapiMaxProtection` — max RFC 1961 protection level after GSSAPI: `1` integrity, `2` confidentiality, `3` selective. Default `1`.
- `IdleTimeoutMs` / `ConnectTimeoutMs` / `SendTimeoutMs` / `ReceiveTimeoutMs` — TCP timeouts (milliseconds).
- `DnsSendTimeoutMs` / `DnsReceiveTimeoutMs` — DNS query timeouts.
- `UdpAssociateIdleTimeoutMs` — UDP ASSOCIATE idle timeout.
- `SendBufferSize` / `ReceiveBufferSize` / `BufferSize` — socket and relay buffer sizes.
- `NoDelay` — TCP_NODELAY.
- `KeepAlive` / `TcpKeepAliveTime` / `TcpKeepAliveInterval` / `TcpKeepAliveRetryCount` — TCP keepalive.
- `LingerEnabled` / `LingerTimeoutSec` — SO_LINGER.

## Logging

- Console logging (Serilog-style levels: information, warning, error).
- Friendly mappings add a suffix like `(MyHost)` to IPs/endpoints in log messages.

## Security and operations

- Handshake/request timeouts to mitigate slow-client issues.
- UDP relay source control to reduce open-proxy abuse risk.
- Connection limits and orderly teardown of active work on shutdown.
- If `proxy.json` is missing, the app exits with a clear error and a hint about `--config`.

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE).
