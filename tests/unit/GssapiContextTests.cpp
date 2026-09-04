#include "../TestFramework.h"

#include "../../server/protocol/GssapiContext.h"

TEST(GssapiContext, DefaultsAndProtectionLevel) {
    GssapiContext ctx;
    EXPECT_FALSE(ctx.Complete());
    EXPECT_EQ(ctx.ProtectionLevel(), 1);
    ctx.SetProtectionLevel(2);
    EXPECT_EQ(ctx.ProtectionLevel(), 2);
    EXPECT_TRUE(ctx.ClientName().empty());
}

TEST(GssapiContext, ResetIsSafeBeforeAcquire) {
    GssapiContext ctx;
    ctx.Reset();
    EXPECT_FALSE(ctx.Complete());
}

TEST(GssapiContext, WrapUnwrapFailWithoutContext) {
    GssapiContext ctx;
    std::vector<uint8_t> out;
    const uint8_t payload[] = {1, 2, 3};
    EXPECT_FALSE(ctx.Wrap(payload, sizeof(payload), false, out));
    EXPECT_FALSE(ctx.Unwrap(payload, sizeof(payload), out));
}

TEST(GssapiContext, AcceptWithoutCredentialsFails) {
    GssapiContext ctx;
    std::vector<uint8_t> token;
    const uint8_t junk[] = {0x60, 0x00};
    const auto status = ctx.AcceptToken(junk, sizeof(junk), token);
    EXPECT_EQ(static_cast<int>(status), static_cast<int>(GssapiContext::AcceptStatus::Failed));
}

TEST(GssapiContext, AcquireDefaultCredentialsSmoke) {
    GssapiContext ctx;
    // May succeed or fail depending on machine/domain; must not crash.
    (void)ctx.AcquireDefaultCredentials();
    ctx.Reset();
    EXPECT_TRUE(true);
}
