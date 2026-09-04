#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>

namespace test {

struct Failure : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Case {
    const char* suite;
    const char* name;
    void (*fn)();
};

inline std::vector<Case>& Registry() {
    static std::vector<Case> cases;
    return cases;
}

struct Registrar {
    Registrar(const char* suite, const char* name, void (*fn)()) {
        Registry().push_back(Case{suite, name, fn});
    }
};

namespace detail {

inline HANDLE Console() {
    return GetStdHandle(STD_OUTPUT_HANDLE);
}

inline WORD DefaultAttrs() {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (GetConsoleScreenBufferInfo(Console(), &info)) {
        return info.wAttributes;
    }
    return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
}

inline void WriteColored(WORD color, std::string_view text) {
    HANDLE console = Console();
    const WORD original = DefaultAttrs();
    SetConsoleTextAttribute(console, color);
    std::cout << text << std::flush;
    SetConsoleTextAttribute(console, original);
}

}  // namespace detail

inline int RunAll() {
    constexpr WORD kGreen = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    constexpr WORD kRed = FOREGROUND_RED | FOREGROUND_INTENSITY;
    constexpr WORD kWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;

    int failed = 0;
    int passed = 0;
    for (const auto& c : Registry()) {
        try {
            c.fn();
            ++passed;
            std::cout << "[ ";
            detail::WriteColored(kGreen, "PASS");
            std::cout << " ] " << c.suite << '.' << c.name << '\n';
        } catch (const Failure& ex) {
            ++failed;
            std::cout << "[ ";
            detail::WriteColored(kRed, "FAIL");
            std::cout << " ] " << c.suite << '.' << c.name << "\n  " << ex.what() << '\n';
        } catch (const std::exception& ex) {
            ++failed;
            std::cout << "[ ";
            detail::WriteColored(kRed, "FAIL");
            std::cout << " ] " << c.suite << '.' << c.name
                      << "\n  unexpected exception: " << ex.what() << '\n';
        } catch (...) {
            ++failed;
            std::cout << "[ ";
            detail::WriteColored(kRed, "FAIL");
            std::cout << " ] " << c.suite << '.' << c.name << "\n  unknown exception\n";
        }
    }

    std::cout << '\n';
    detail::WriteColored(kGreen, std::to_string(passed) + " passed");
    std::cout << ", ";
    detail::WriteColored(failed ? kRed : kWhite, std::to_string(failed) + " failed");
    std::cout << ", " << (passed + failed) << " total\n";
    return failed == 0 ? 0 : 1;
}

inline void Fail(const char* expr, const char* file, int line, const std::string& detail = {}) {
    std::ostringstream oss;
    oss << file << '(' << line << "): EXPECT(" << expr << ')';
    if (!detail.empty()) oss << " — " << detail;
    throw Failure(oss.str());
}

}  // namespace test

#define TEST(suite, name)                                                         \
    static void test_##suite##_##name();                                          \
    static ::test::Registrar registrar_##suite##_##name(#suite, #name,            \
                                                        &test_##suite##_##name);  \
    static void test_##suite##_##name()

#define EXPECT_TRUE(expr)                                                         \
    do {                                                                          \
        if (!(expr)) ::test::Fail(#expr, __FILE__, __LINE__);                     \
    } while (0)

#define EXPECT_FALSE(expr) EXPECT_TRUE(!(expr))

#define EXPECT_EQ(a, b)                                                           \
    do {                                                                          \
        const auto& _a = (a);                                                     \
        const auto& _b = (b);                                                     \
        if (!(_a == _b)) {                                                        \
            std::ostringstream _oss;                                              \
            _oss << "left=" << _a << " right=" << _b;                             \
            ::test::Fail(#a " == " #b, __FILE__, __LINE__, _oss.str());           \
        }                                                                         \
    } while (0)

#define EXPECT_NE(a, b)                                                           \
    do {                                                                          \
        const auto& _a = (a);                                                     \
        const auto& _b = (b);                                                     \
        if (_a == _b) {                                                           \
            std::ostringstream _oss;                                              \
            _oss << "both=" << _a;                                                \
            ::test::Fail(#a " != " #b, __FILE__, __LINE__, _oss.str());           \
        }                                                                         \
    } while (0)

#define EXPECT_THROW(expr, ExType)                                                \
    do {                                                                          \
        bool _threw = false;                                                      \
        try {                                                                     \
            (void)(expr);                                                         \
        } catch (const ExType&) {                                                 \
            _threw = true;                                                        \
        } catch (...) {                                                           \
            ::test::Fail(#expr " throws " #ExType, __FILE__, __LINE__,            \
                         "wrong exception type");                                 \
        }                                                                         \
        if (!_threw) {                                                            \
            ::test::Fail(#expr " throws " #ExType, __FILE__, __LINE__,            \
                         "no exception");                                         \
        }                                                                         \
    } while (0)
