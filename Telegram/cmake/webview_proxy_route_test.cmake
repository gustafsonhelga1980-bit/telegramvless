# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_webview_proxy_route)
init_target(test_webview_proxy_route "(tests)")

nice_target_sources(test_webview_proxy_route ${src_loc}
PRIVATE
    tests/test_webview_proxy_route.cpp
)

target_link_libraries(test_webview_proxy_route
PRIVATE
    desktop-app::lib_webview
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Network
)

set_target_properties(test_webview_proxy_route PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_test(
    NAME webview_proxy_route_policy
    COMMAND "../$<CONFIG>/test_webview_proxy_route" --policy-only
)
set_tests_properties(webview_proxy_route_policy PROPERTIES TIMEOUT 30)

add_custom_target(check_webview_proxy_route_policy
    COMMAND $<TARGET_FILE:test_webview_proxy_route> --policy-only
    VERBATIM
)

add_dependencies(
    check_webview_proxy_route_policy
    test_webview_proxy_route
)

add_dependencies(Telegram check_webview_proxy_route_policy)
