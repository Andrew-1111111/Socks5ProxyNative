#include "GssapiContext.h"

#include "../../utils/Logger.h"

#include <cstring>

#pragma comment(lib, "secur32.lib")

namespace {
constexpr wchar_t kPackageName[] = L"Negotiate";
}

GssapiContext::GssapiContext() {
    SecInvalidateHandle(&credentials_);
    SecInvalidateHandle(&context_);
}

GssapiContext::~GssapiContext() {
    Reset();
}

void GssapiContext::Reset() {
    if (haveContext_) {
        DeleteSecurityContext(&context_);
        SecInvalidateHandle(&context_);
        haveContext_ = false;
    }
    if (haveCredentials_) {
        FreeCredentialsHandle(&credentials_);
        SecInvalidateHandle(&credentials_);
        haveCredentials_ = false;
    }
    if (packageInfo_) {
        FreeContextBuffer(packageInfo_);
        packageInfo_ = nullptr;
    }
    complete_ = false;
    contextAttrs_ = 0;
    clientName_.clear();
    protectionLevel_ = 1;
}

bool GssapiContext::EnsurePackageInfo() {
    if (packageInfo_) return true;
    const SECURITY_STATUS st = QuerySecurityPackageInfoW(const_cast<SEC_WCHAR*>(kPackageName), &packageInfo_);
    return st == SEC_E_OK && packageInfo_ != nullptr;
}

bool GssapiContext::AcquireDefaultCredentials() {
    Reset();
    TimeStamp lifetime{};
    const SECURITY_STATUS st = AcquireCredentialsHandleW(
        nullptr,
        const_cast<SEC_WCHAR*>(kPackageName),
        SECPKG_CRED_INBOUND,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &credentials_,
        &lifetime);
    if (st != SEC_E_OK) {
        Logger::Instance().Warning("GSSAPI: AcquireCredentialsHandle failed: {Status}", static_cast<int>(st));
        return false;
    }
    haveCredentials_ = true;
    return EnsurePackageInfo();
}

GssapiContext::AcceptStatus GssapiContext::AcceptToken(const uint8_t* input, size_t inputLen,
                                                       std::vector<uint8_t>& outputToken) {
    outputToken.clear();
    if (!haveCredentials_ && !AcquireDefaultCredentials()) {
        return AcceptStatus::Failed;
    }

    SecBufferDesc outDesc{};
    SecBuffer outBuf{};
    outBuf.BufferType = SECBUFFER_TOKEN;
    outBuf.cbBuffer = packageInfo_ ? packageInfo_->cbMaxToken : 65536;
    std::vector<uint8_t> outStorage(outBuf.cbBuffer);
    outBuf.pvBuffer = outStorage.data();
    outDesc.ulVersion = SECBUFFER_VERSION;
    outDesc.cBuffers = 1;
    outDesc.pBuffers = &outBuf;

    SecBufferDesc inDesc{};
    SecBuffer inBuf{};
    if (input && inputLen > 0) {
        inBuf.BufferType = SECBUFFER_TOKEN;
        inBuf.cbBuffer = static_cast<ULONG>(inputLen);
        inBuf.pvBuffer = const_cast<uint8_t*>(input);
        inDesc.ulVersion = SECBUFFER_VERSION;
        inDesc.cBuffers = 1;
        inDesc.pBuffers = &inBuf;
    }

    ULONG contextAttr = 0;
    TimeStamp lifetime{};
    const ULONG req =
        ASC_REQ_CONNECTION | ASC_REQ_MUTUAL_AUTH | ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT |
        ASC_REQ_CONFIDENTIALITY | ASC_REQ_INTEGRITY;

    CtxtHandle* ctxPtr = haveContext_ ? &context_ : nullptr;
    const SECURITY_STATUS st = AcceptSecurityContext(
        &credentials_,
        ctxPtr,
        (input && inputLen > 0) ? &inDesc : nullptr,
        req,
        SECURITY_NATIVE_DREP,
        &context_,
        &outDesc,
        &contextAttr,
        &lifetime);

    haveContext_ = true;
    contextAttrs_ = contextAttr;

    if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
        outputToken.assign(static_cast<uint8_t*>(outBuf.pvBuffer),
                           static_cast<uint8_t*>(outBuf.pvBuffer) + outBuf.cbBuffer);
    }

    if (st == SEC_E_OK) {
        complete_ = true;
        SecPkgContext_NamesW names{};
        if (QueryContextAttributesW(&context_, SECPKG_ATTR_NAMES, &names) == SEC_E_OK && names.sUserName) {
            const int bytes = WideCharToMultiByte(CP_UTF8, 0, names.sUserName, -1, nullptr, 0, nullptr, nullptr);
            if (bytes > 1) {
                clientName_.resize(static_cast<size_t>(bytes - 1));
                WideCharToMultiByte(CP_UTF8, 0, names.sUserName, -1, clientName_.data(), bytes, nullptr, nullptr);
            }
            FreeContextBuffer(names.sUserName);
        }
        return AcceptStatus::Complete;
    }
    if (st == SEC_I_CONTINUE_NEEDED || st == SEC_I_COMPLETE_AND_CONTINUE) {
        return AcceptStatus::ContinueNeeded;
    }

    Logger::Instance().Warning("GSSAPI: AcceptSecurityContext failed: {Status}", static_cast<int>(st));
    return AcceptStatus::Failed;
}

bool GssapiContext::Wrap(const uint8_t* input, size_t inputLen, bool confidentiality,
                         std::vector<uint8_t>& output) {
    output.clear();
    if (!haveContext_ || !complete_ || !input) return false;

    SecPkgContext_Sizes sizes{};
    if (QueryContextAttributesW(&context_, SECPKG_ATTR_SIZES, &sizes) != SEC_E_OK) {
        return false;
    }

    const size_t total = static_cast<size_t>(sizes.cbSecurityTrailer) + inputLen + sizes.cbBlockSize;
    std::vector<uint8_t> buffer(total);
    std::memcpy(buffer.data() + sizes.cbSecurityTrailer, input, inputLen);

    SecBuffer bufs[3]{};
    bufs[0].BufferType = SECBUFFER_TOKEN;
    bufs[0].cbBuffer = sizes.cbSecurityTrailer;
    bufs[0].pvBuffer = buffer.data();
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].cbBuffer = static_cast<ULONG>(inputLen);
    bufs[1].pvBuffer = buffer.data() + sizes.cbSecurityTrailer;
    bufs[2].BufferType = SECBUFFER_PADDING;
    bufs[2].cbBuffer = sizes.cbBlockSize;
    bufs[2].pvBuffer = buffer.data() + sizes.cbSecurityTrailer + inputLen;

    SecBufferDesc desc{};
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 3;
    desc.pBuffers = bufs;

    const ULONG qop = confidentiality ? 0 : SECQOP_WRAP_NO_ENCRYPT;
    if (EncryptMessage(&context_, qop, &desc, 0) != SEC_E_OK) {
        return false;
    }

    output.reserve(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
    output.insert(output.end(), static_cast<uint8_t*>(bufs[0].pvBuffer),
                  static_cast<uint8_t*>(bufs[0].pvBuffer) + bufs[0].cbBuffer);
    output.insert(output.end(), static_cast<uint8_t*>(bufs[1].pvBuffer),
                  static_cast<uint8_t*>(bufs[1].pvBuffer) + bufs[1].cbBuffer);
    output.insert(output.end(), static_cast<uint8_t*>(bufs[2].pvBuffer),
                  static_cast<uint8_t*>(bufs[2].pvBuffer) + bufs[2].cbBuffer);
    return true;
}

bool GssapiContext::Unwrap(const uint8_t* input, size_t inputLen, std::vector<uint8_t>& output) {
    output.clear();
    if (!haveContext_ || !complete_ || !input || inputLen == 0) return false;

    std::vector<uint8_t> buffer(input, input + inputLen);
    SecBuffer bufs[2]{};
    bufs[0].BufferType = SECBUFFER_STREAM;
    bufs[0].cbBuffer = static_cast<ULONG>(buffer.size());
    bufs[0].pvBuffer = buffer.data();
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].cbBuffer = 0;
    bufs[1].pvBuffer = nullptr;

    SecBufferDesc desc{};
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 2;
    desc.pBuffers = bufs;

    ULONG qop = 0;
    if (DecryptMessage(&context_, &desc, 0, &qop) != SEC_E_OK) {
        return false;
    }

    for (ULONG i = 0; i < desc.cBuffers; ++i) {
        if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].pvBuffer && bufs[i].cbBuffer > 0) {
            output.assign(static_cast<uint8_t*>(bufs[i].pvBuffer),
                          static_cast<uint8_t*>(bufs[i].pvBuffer) + bufs[i].cbBuffer);
            return true;
        }
    }
    return false;
}
