# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_call_proxy_route)
init_target(test_call_proxy_route "(tests)")

set(call_proxy_tgcalls_dir ${third_party_loc}/tgcalls)
set(call_proxy_tgcalls_loc ${call_proxy_tgcalls_dir}/tgcalls)

target_include_directories(test_call_proxy_route
PRIVATE
    ${call_proxy_tgcalls_loc}
)

nice_target_sources(test_call_proxy_route ${src_loc}
PRIVATE
    tests/test_call_proxy_route.cpp
)

nice_target_sources(test_call_proxy_route ${call_proxy_tgcalls_loc}
PRIVATE
    v2/RawTcpSocket.cpp
    v2/RawTcpSocket.h
    v2/RawTcpSocketFactory.cpp
    v2/RawTcpSocketFactory.h
    v2/Socks5ProxySocket.cpp
    v2/Socks5ProxySocket.h
)

target_link_libraries(test_call_proxy_route
PRIVATE
    desktop-app::external_webrtc
)

set_target_properties(test_call_proxy_route PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_test(
    NAME call_proxy_route_policy
    COMMAND "../$<CONFIG>/test_call_proxy_route" --policy-only
)
set_tests_properties(call_proxy_route_policy PROPERTIES TIMEOUT 30)

add_custom_target(check_call_proxy_route_policy
    COMMAND $<TARGET_FILE:test_call_proxy_route> --policy-only
    VERBATIM
)

add_dependencies(check_call_proxy_route_policy test_call_proxy_route)

add_dependencies(Telegram check_call_proxy_route_policy)

add_executable(test_socks5_proxy_socket)
init_target(test_socks5_proxy_socket "(tests)")

target_include_directories(test_socks5_proxy_socket
PRIVATE
    ${call_proxy_tgcalls_loc}
)

nice_target_sources(test_socks5_proxy_socket ${src_loc}
PRIVATE
    tests/test_socks5_proxy_socket.cpp
)

nice_target_sources(test_socks5_proxy_socket ${call_proxy_tgcalls_loc}
PRIVATE
    v2/Socks5ProxySocket.cpp
    v2/Socks5ProxySocket.h
)

target_link_libraries(test_socks5_proxy_socket
PRIVATE
    desktop-app::external_webrtc
)

set_target_properties(test_socks5_proxy_socket PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_test(
    NAME socks5_proxy_socket
    COMMAND "../$<CONFIG>/test_socks5_proxy_socket"
)
set_tests_properties(socks5_proxy_socket PROPERTIES TIMEOUT 30)

add_custom_target(check_socks5_proxy_socket
    COMMAND $<TARGET_FILE:test_socks5_proxy_socket>
    VERBATIM
)

add_dependencies(check_socks5_proxy_socket test_socks5_proxy_socket)

add_dependencies(Telegram check_socks5_proxy_socket)
