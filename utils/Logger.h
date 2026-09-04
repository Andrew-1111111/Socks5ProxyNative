#pragma once

#include <concepts>
#include <mutex>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>
#include <algorithm>

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Off
};

enum class LogValueKind {
    Text,
    String,
    Number,
    Boolean,
    Scalar
};

struct LogValue {
    std::string text;
    LogValueKind kind = LogValueKind::String;
};

class Logger {
public:
    static Logger& Instance();

    void SetMinLevel(LogLevel level);
    bool IsLevelEnabled(LogLevel level) const;

    void Debug(std::string_view message);
    void Info(std::string_view message);
    void Warning(std::string_view message);
    void Error(std::string_view message);

    template <typename... Args>
    void Debug(std::string_view tmpl, const Args&... args) {
        if (!IsLevelEnabled(LogLevel::Debug)) return;
        LogTemplate(LogLevel::Debug, tmpl, MakeValues(args)...);
    }

    template <typename... Args>
    void Info(std::string_view tmpl, const Args&... args) {
        if (!IsLevelEnabled(LogLevel::Info)) return;
        LogTemplate(LogLevel::Info, tmpl, MakeValues(args)...);
    }

    template <typename... Args>
    void Warning(std::string_view tmpl, const Args&... args) {
        if (!IsLevelEnabled(LogLevel::Warning)) return;
        LogTemplate(LogLevel::Warning, tmpl, MakeValues(args)...);
    }

    template <typename... Args>
    void Error(std::string_view tmpl, const Args&... args) {
        if (!IsLevelEnabled(LogLevel::Error)) return;
        LogTemplate(LogLevel::Error, tmpl, MakeValues(args)...);
    }

private:
    Logger() = default;

    void Log(LogLevel level, std::string_view message);
    void LogTemplate(LogLevel level, std::string_view tmpl, std::vector<LogValue> values);
    template <typename... Values>
    void LogTemplate(LogLevel level, std::string_view tmpl, Values&&... values) {
        std::vector<LogValue> list;
        list.reserve(sizeof...(Values));
        (list.push_back(std::forward<Values>(values)), ...);
        LogTemplate(level, tmpl, std::move(list));
    }

    static const char* LevelName(LogLevel level);

    static LogValue MakeValues(bool value) {
        return LogValue{value ? "true" : "false", LogValueKind::Boolean};
    }

    static LogValue MakeValues(const char* value) {
        return LogValue{value ? value : "", LogValueKind::String};
    }

    static LogValue MakeValues(std::string_view value) {
        return LogValue{std::string(value), LogValueKind::String};
    }

    static LogValue MakeValues(const std::string& value) {
        return LogValue{value, LogValueKind::String};
    }

    template <typename T>
        requires std::integral<T> && (!std::same_as<std::remove_cvref_t<T>, bool>)
    static LogValue MakeValues(T value) {
        return LogValue{std::to_string(value), LogValueKind::Number};
    }

    template <typename T>
        requires std::floating_point<T>
    static LogValue MakeValues(T value) {
        return LogValue{std::to_string(value), LogValueKind::Number};
    }

    mutable std::mutex mutex_;
    LogLevel minLevel_ = LogLevel::Info;
};
