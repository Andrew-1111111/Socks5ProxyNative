#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <sspi.h>

/// Windows SSPI (Negotiate) acceptor for SOCKS5 GSS-API auth (RFC 1961).
class GssapiContext {
public:
    enum class AcceptStatus { ContinueNeeded, Complete, Failed };

    GssapiContext();
    ~GssapiContext();

    GssapiContext(const GssapiContext&) = delete;
    GssapiContext& operator=(const GssapiContext&) = delete;

    bool AcquireDefaultCredentials();
    AcceptStatus AcceptToken(const uint8_t* input, size_t inputLen, std::vector<uint8_t>& outputToken);
    bool Wrap(const uint8_t* input, size_t inputLen, bool confidentiality, std::vector<uint8_t>& output);
    bool Unwrap(const uint8_t* input, size_t inputLen, std::vector<uint8_t>& output);
    void Reset();

    bool Complete() const { return complete_; }
    uint8_t ProtectionLevel() const { return protectionLevel_; }
    void SetProtectionLevel(uint8_t level) { protectionLevel_ = level; }
    bool ConfidentialityAvailable() const { return (contextAttrs_ & ASC_RET_CONFIDENTIALITY) != 0; }
    bool IntegrityAvailable() const { return (contextAttrs_ & ASC_RET_INTEGRITY) != 0; }
    const std::string& ClientName() const { return clientName_; }

private:
    bool EnsurePackageInfo();

    CredHandle credentials_{};
    CtxtHandle context_{};
    bool haveCredentials_ = false;
    bool haveContext_ = false;
    bool complete_ = false;
    ULONG contextAttrs_ = 0;
    uint8_t protectionLevel_ = 1;
    std::string clientName_;
    PSecPkgInfoW packageInfo_ = nullptr;
};
