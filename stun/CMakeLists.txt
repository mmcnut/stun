add_executable(stun stun/stun.cpp)


if(ENABLE_TESTING)
    enable_testing()
    add_executable(
        stun_test stun/stun.test.cpp
    )
    target_link_libraries(
        stun_test
        GTest::gtest_main
    )
    include(GoogleTest)
    gtest_discover_tests(stun)
endif()
