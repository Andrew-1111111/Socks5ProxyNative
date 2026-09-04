#include "../TestFramework.h"

#include "../../utils/Logger.h"

TEST(Logger, MinLevelFiltersMessages) {
    Logger::Instance().SetMinLevel(LogLevel::Warning);
    EXPECT_FALSE(Logger::Instance().IsLevelEnabled(LogLevel::Debug));
    EXPECT_FALSE(Logger::Instance().IsLevelEnabled(LogLevel::Info));
    EXPECT_TRUE(Logger::Instance().IsLevelEnabled(LogLevel::Warning));
    EXPECT_TRUE(Logger::Instance().IsLevelEnabled(LogLevel::Error));

    Logger::Instance().SetMinLevel(LogLevel::Off);
    EXPECT_FALSE(Logger::Instance().IsLevelEnabled(LogLevel::Error));
    EXPECT_FALSE(Logger::Instance().IsLevelEnabled(LogLevel::Warning));

    Logger::Instance().SetMinLevel(LogLevel::Debug);
    EXPECT_TRUE(Logger::Instance().IsLevelEnabled(LogLevel::Debug));
    Logger::Instance().SetMinLevel(LogLevel::Off);
}

TEST(Logger, OverloadsDoNotThrowWhenDisabled) {
    Logger::Instance().SetMinLevel(LogLevel::Off);
    Logger::Instance().Info("plain");
    Logger::Instance().Warning("value={Value}", 42);
    Logger::Instance().Error("flag={Flag} name={Name}", true, std::string("x"));
    Logger::Instance().Debug("unused={N}", 1);
    EXPECT_TRUE(true);
}
