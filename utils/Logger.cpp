#include "Logger.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

namespace {

// Serilog.Sinks.Console SystemConsoleTheme.Literate
constexpr WORD kGray = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
constexpr WORD kWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr WORD kYellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
constexpr WORD kCyan = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr WORD kMagenta = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr WORD kBlue = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr WORD kGreen = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
constexpr WORD kRedBg = BACKGROUND_RED;
constexpr WORD kKeepBg = 0xFF00;

struct Style {
    WORD foreground;
    WORD background = kKeepBg;
};

Style StyleSecondary() { return {kGray}; }
Style StyleText() { return {kWhite}; }
Style StyleString() { return {kCyan}; }
Style StyleNumber() { return {kMagenta}; }
Style StyleBoolean() { return {kBlue}; }
Style StyleScalar() { return {kGreen}; }

Style StyleLevel(LogLevel level) {
    switch (level) {
    case LogLevel::Debug: return {kGray};
    case LogLevel::Info: return {kWhite};
    case LogLevel::Warning: return {kYellow};
    case LogLevel::Error: return {kWhite, kRedBg};
    }
    return {kWhite};
}

Style StyleFor(LogValueKind kind) {
    switch (kind) {
    case LogValueKind::Text: return StyleText();
    case LogValueKind::String: return StyleString();
    case LogValueKind::Number: return StyleNumber();
    case LogValueKind::Boolean: return StyleBoolean();
    case LogValueKind::Scalar: return StyleScalar();
    }
    return StyleText();
}

WORD Combine(WORD current, Style style) {
    const WORD bg = (style.background == kKeepBg) ? (current & 0xF0) : (style.background & 0xF0);
    return static_cast<WORD>((style.foreground & 0x0F) | bg);
}

void WriteStyled(HANDLE console, WORD& currentAttrs, Style style, const char* text, size_t length) {
    const WORD attrs = Combine(currentAttrs, style);
    SetConsoleTextAttribute(console, attrs);
    currentAttrs = attrs;
    if (length == 0) return;
    DWORD written = 0;
    WriteConsoleA(console, text, static_cast<DWORD>(length), &written, nullptr);
}

void WriteStyled(HANDLE console, WORD& currentAttrs, Style style, std::string_view text) {
    WriteStyled(console, currentAttrs, style, text.data(), text.size());
}

const char* LevelNameLocal(LogLevel level) {
    switch (level) {
    case LogLevel::Debug: return "DBG";
    case LogLevel::Info: return "INF";
    case LogLevel::Warning: return "WRN";
    case LogLevel::Error: return "ERR";
    }
    return "INF";
}

void FormatTime(char (&timeBuf)[16]) {
    using clock = std::chrono::system_clock;
    const auto now = clock::now();
    const auto time = clock::to_time_t(now);
    std::tm local{};
    localtime_s(&local, &time);
    std::strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &local);
}

void WriteLinePrefix(HANDLE console, WORD& current, LogLevel level, const char* timeBuf) {
    WriteStyled(console, current, StyleSecondary(), "[", 1);
    WriteStyled(console, current, StyleSecondary(), timeBuf, std::strlen(timeBuf));
    WriteStyled(console, current, StyleSecondary(), " ", 1);
    WriteStyled(console, current, StyleLevel(level), LevelNameLocal(level), 3);
    WriteStyled(console, current, StyleSecondary(), "] ", 2);
}

void RenderTemplate(HANDLE console, WORD& current, std::string_view tmpl,
                    const std::vector<LogValue>& values) {
    size_t argIndex = 0;
    size_t i = 0;
    while (i < tmpl.size()) {
        if (tmpl[i] == '{') {
            if (i + 1 < tmpl.size() && tmpl[i + 1] == '{') {
                WriteStyled(console, current, StyleText(), "{", 1);
                i += 2;
                continue;
            }

            const size_t end = tmpl.find('}', i + 1);
            if (end == std::string_view::npos) {
                WriteStyled(console, current, StyleText(), tmpl.substr(i));
                break;
            }

            // Property may include Serilog format: {Port}, {Command:X2}
            if (argIndex < values.size()) {
                const auto& value = values[argIndex++];
                WriteStyled(console, current, StyleFor(value.kind), value.text);
            }
            i = end + 1;
            continue;
        }

        if (tmpl[i] == '}' && i + 1 < tmpl.size() && tmpl[i + 1] == '}') {
            WriteStyled(console, current, StyleText(), "}", 1);
            i += 2;
            continue;
        }

        const size_t start = i;
        while (i < tmpl.size() && tmpl[i] != '{' &&
               !(tmpl[i] == '}' && i + 1 < tmpl.size() && tmpl[i + 1] == '}')) {
            ++i;
        }
        WriteStyled(console, current, StyleText(), tmpl.substr(start, i - start));
    }
}

std::string RenderPlain(std::string_view tmpl, const std::vector<LogValue>& values) {
    std::string plain;
    plain.reserve(tmpl.size() + 64);
    size_t argIndex = 0;
    for (size_t i = 0; i < tmpl.size();) {
        if (tmpl[i] == '{') {
            if (i + 1 < tmpl.size() && tmpl[i + 1] == '{') {
                plain.push_back('{');
                i += 2;
                continue;
            }
            const size_t end = tmpl.find('}', i + 1);
            if (end == std::string_view::npos) {
                plain.append(tmpl.substr(i));
                break;
            }
            if (argIndex < values.size()) {
                plain += values[argIndex++].text;
            }
            i = end + 1;
            continue;
        }
        if (tmpl[i] == '}' && i + 1 < tmpl.size() && tmpl[i + 1] == '}') {
            plain.push_back('}');
            i += 2;
            continue;
        }
        plain.push_back(tmpl[i++]);
    }
    return plain;
}

}  // namespace

Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

void Logger::SetMinLevel(LogLevel level) {
    std::lock_guard lock(mutex_);
    minLevel_ = level;
}

bool Logger::IsLevelEnabled(LogLevel level) const {
    std::lock_guard lock(mutex_);
    return static_cast<int>(level) >= static_cast<int>(minLevel_);
}

void Logger::Debug(std::string_view message) { Log(LogLevel::Debug, message); }
void Logger::Info(std::string_view message) { Log(LogLevel::Info, message); }
void Logger::Warning(std::string_view message) { Log(LogLevel::Warning, message); }
void Logger::Error(std::string_view message) { Log(LogLevel::Error, message); }

void Logger::Log(LogLevel level, std::string_view message) {
    LogTemplate(level, "{}", std::vector<LogValue>{LogValue{std::string(message), LogValueKind::Text}});
}

void Logger::LogTemplate(LogLevel level, std::string_view tmpl, std::vector<LogValue> values) {
    std::lock_guard lock(mutex_);
    if (static_cast<int>(level) < static_cast<int>(minLevel_)) {
        return;
    }

    char timeBuf[16]{};
    FormatTime(timeBuf);

    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    const bool isConsole = console != INVALID_HANDLE_VALUE && console != nullptr &&
                           GetConsoleMode(console, &mode);

    if (!isConsole) {
        const std::string plain = (tmpl == "{}" && values.size() == 1)
                                      ? values[0].text
                                      : RenderPlain(tmpl, values);
        std::printf("[%s %s] %s\n", timeBuf, LevelNameLocal(level), plain.c_str());
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO info{};
    GetConsoleScreenBufferInfo(console, &info);
    WORD current = info.wAttributes;
    const WORD original = current;

    WriteLinePrefix(console, current, level, timeBuf);

    if (tmpl == "{}" && values.size() == 1 && values[0].kind == LogValueKind::Text) {
        WriteStyled(console, current, StyleText(), values[0].text);
    } else {
        RenderTemplate(console, current, tmpl, values);
    }

    WriteStyled(console, current, StyleSecondary(), "\n", 1);
    SetConsoleTextAttribute(console, original);
}

const char* Logger::LevelName(LogLevel level) {
    return LevelNameLocal(level);
}
