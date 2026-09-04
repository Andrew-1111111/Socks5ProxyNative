# CMakeList.txt: Socks5Proxy (C++ port of SimpleSocks5Proxy)
cmake_minimum_required(VERSION 3.16)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project(Socks5Proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Socks5Proxy
  Socks5Proxy.cpp
  Socks5Proxy.rc
  config/NetworkConfiguration.cpp
  config/ProxyConfiguration.cpp
  network/Network.cpp
  network/Iocp.cpp
  network/TcpAcceptor.cpp
  dns/DnsClient.cpp
  dns/DnsResolver.cpp
  utils/Logger.cpp
  utils/Application.cpp
  friendly/FriendlyNameResolver.cpp
  helper/NetworkMonitoring.cpp
  server/ProxyServer.cpp
  server/protocol/UdpRelay.cpp
  server/protocol/GssapiContext.cpp
  server/protocol/Socks5Session.cpp
)

target_include_directories(Socks5Proxy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if (WIN32)
  target_compile_definitions(Socks5Proxy PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(Socks5Proxy PRIVATE ws2_32 mswsock iphlpapi shell32 advapi32 secur32)
endif()

add_custom_command(TARGET Socks5Proxy POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/proxy.json"
    "$<TARGET_FILE_DIR:Socks5Proxy>/proxy.json"
)

option(SOCKS5PROXY_BUILD_TESTS "Build unit tests" ON)
if (SOCKS5PROXY_BUILD_TESTS)
  enable_testing()
  add_executable(Socks5Proxy.Tests
    tests/main.cpp
    tests/unit/DnsClientTests.cpp
    tests/unit/ProxyConfigurationTests.cpp
    tests/unit/NetworkUtilsTests.cpp
    tests/unit/FriendlyNameResolverTests.cpp
    tests/unit/Socks5ConstantsTests.cpp
    tests/unit/NetworkMonitoringTests.cpp
    tests/unit/NetworkConfigurationTests.cpp
    tests/unit/LoggerTests.cpp
    tests/unit/ApplicationTests.cpp
    tests/unit/GssapiContextTests.cpp
    tests/unit/IocpTests.cpp
    tests/unit/TcpAcceptorTests.cpp
    tests/unit/DnsResolverTests.cpp
    tests/integration/IntegrationTests.cpp
    dns/DnsClient.cpp
    dns/DnsResolver.cpp
    config/ProxyConfiguration.cpp
    config/NetworkConfiguration.cpp
    network/Network.cpp
    network/Iocp.cpp
    network/TcpAcceptor.cpp
    utils/Logger.cpp
    utils/Application.cpp
    friendly/FriendlyNameResolver.cpp
    helper/NetworkMonitoring.cpp
    server/ProxyServer.cpp
    server/protocol/GssapiContext.cpp
    server/protocol/Socks5Session.cpp
    server/protocol/UdpRelay.cpp
  )
  target_include_directories(Socks5Proxy.Tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration
  )
  target_compile_features(Socks5Proxy.Tests PRIVATE cxx_std_20)
  if (WIN32)
    target_compile_definitions(Socks5Proxy.Tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(Socks5Proxy.Tests PRIVATE ws2_32 mswsock iphlpapi shell32 advapi32 secur32)
  endif()
  if (MSVC)
    target_compile_options(Socks5Proxy.Tests PRIVATE /Gy)
    target_link_options(Socks5Proxy.Tests PRIVATE /OPT:REF)
  endif()
  add_test(NAME Socks5Proxy.Tests COMMAND Socks5Proxy.Tests --no-pause)
endif()
