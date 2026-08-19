# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_vless_profile)
init_target(test_vless_profile "(tests)")

target_include_directories(test_vless_profile
PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/lib_base
    ${src_loc}
)

nice_target_sources(test_vless_profile ${src_loc}
PRIVATE
    core/vless_profile.cpp
    core/vless_profile.h
    tests/test_vless_profile.cpp
)

target_link_libraries(test_vless_profile
PRIVATE
    desktop-app::external_gsl
    Qt${QT_VERSION_MAJOR}::Core
)

set_target_properties(test_vless_profile PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_test(
    NAME vless_profile
    COMMAND "../$<CONFIG>/test_vless_profile"
)
set_tests_properties(vless_profile PROPERTIES TIMEOUT 30)

add_custom_target(check_vless_profile
    COMMAND $<TARGET_FILE:test_vless_profile>
    VERBATIM
)

add_dependencies(check_vless_profile test_vless_profile)

add_dependencies(Telegram check_vless_profile)
