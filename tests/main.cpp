#include "TestFramework.h"

#include "../utils/Logger.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#include <cstdio>
#include <iostream>
#include <string>

#include <io.h>

#pragma comment(lib, "ws2_32.lib")

namespace {

bool ShouldPause(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--no-pause") {
            return false;
        }
    }
    return _isatty(_fileno(stdout)) != 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    Logger::Instance().SetMinLevel(LogLevel::Off);

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed.\n";
        if (ShouldPause(argc, argv)) {
            std::system("pause");
        }
        return 2;
    }

    const int code = test::RunAll();
    WSACleanup();

    if (ShouldPause(argc, argv)) {
        std::system("pause");
    }
    return code;
}
