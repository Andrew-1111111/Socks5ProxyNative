#include "../TestFramework.h"

#include "../../helper/NetworkMonitoring.h"

#include <atomic>
#include <chrono>
#include <thread>

TEST(NetworkMonitoring, RestartRequestedInitiallyFalse) {
    NetworkMonitoring monitoring;
    EXPECT_FALSE(monitoring.RestartRequested());
}

TEST(NetworkMonitoring, PrepareRestartAfterDelayZeroMarksImmediately) {
    NetworkMonitoring monitoring;
    std::atomic<bool> stop{false};
    monitoring.PrepareRestartAfterDelay(0, stop);
    EXPECT_TRUE(monitoring.RestartRequested());
}

TEST(NetworkMonitoring, PrepareRestartCancelledByStopFlag) {
    NetworkMonitoring monitoring;
    std::atomic<bool> stop{false};
    std::thread stopper([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        stop.store(true);
    });
    monitoring.PrepareRestartAfterDelay(30, stop);
    stopper.join();
    EXPECT_FALSE(monitoring.RestartRequested());
}

TEST(NetworkMonitoring, StartupRestartDelayConstant) {
    EXPECT_EQ(NetworkMonitoring::StartupRestartDelaySec, 30);
}

TEST(NetworkMonitoring, CheckInterfaceAllowsListenerAnyAndLoopback) {
    NetworkMonitoring monitoring;
    EXPECT_TRUE(monitoring.CheckInterface("0.0.0.0", "Listener"));
    EXPECT_TRUE(monitoring.CheckInterface("::", "Listener"));
    EXPECT_TRUE(monitoring.CheckInterface("127.0.0.1", "Listener"));
    EXPECT_TRUE(monitoring.CheckInterface("::1", "Listener"));
}

TEST(NetworkMonitoring, CheckInterfaceRejectsMissingOutput) {
    NetworkMonitoring monitoring;
    EXPECT_FALSE(monitoring.CheckInterface("203.0.113.200", "Output"));
}

TEST(NetworkMonitoring, CheckInterfaceAllowsOutputAny) {
    NetworkMonitoring monitoring;
    EXPECT_TRUE(monitoring.CheckInterface("0.0.0.0", "Output"));
}

TEST(NetworkMonitoring, RunStopsWhenStopFlagSet) {
    NetworkMonitoring monitoring;
    std::atomic<bool> stop{false};
    std::thread runner([&] {
        monitoring.Run("0.0.0.0", "0.0.0.0", stop);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    stop.store(true);
    runner.join();
    EXPECT_FALSE(monitoring.RestartRequested());
}

TEST(NetworkMonitoring, RunRequestsRestartWhenOutputMissing) {
    NetworkMonitoring monitoring;
    std::atomic<bool> stop{false};
    // Listener any/loopback always OK; bogus output fails every cycle (~5s).
    // After 3 failures the monitor requests restart (~10-15s).
    std::thread runner([&] {
        monitoring.Run("127.0.0.1", "203.0.113.200", stop);
    });
    runner.join();
    EXPECT_TRUE(monitoring.RestartRequested());
    EXPECT_TRUE(stop.load());
}
