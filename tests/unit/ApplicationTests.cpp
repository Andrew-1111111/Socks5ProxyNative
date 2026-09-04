#include "../TestFramework.h"

#include "../../utils/Application.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

TEST(Application, SingleInstanceGuardDetectsSecondInstance) {
    const std::wstring id = L"Socks5Proxy_UnitTest_SingleInstance_" + std::to_wstring(GetCurrentProcessId());
    SingleInstanceGuard first(id);
    EXPECT_FALSE(first.IsRunning());

    SingleInstanceGuard second(id);
    EXPECT_TRUE(second.IsRunning());
}

TEST(Application, SingleInstanceGuardReleasesOnDestruction) {
    const std::wstring id = L"Socks5Proxy_UnitTest_SingleInstance_Release_" + std::to_wstring(GetCurrentProcessId());
    {
        SingleInstanceGuard first(id);
        EXPECT_FALSE(first.IsRunning());
    }
    SingleInstanceGuard again(id);
    EXPECT_FALSE(again.IsRunning());
}

TEST(Application, IsElevatedReturnsBool) {
    (void)AdminLauncher::IsElevated();
    EXPECT_TRUE(true);
}
