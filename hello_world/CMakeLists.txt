add_executable(hello_world hello_world/hello_world.cpp)


if(ENABLE_TESTING)
    enable_testing()
    add_executable(
        hello_world_test hello_world/hello_world.test.cpp
    )
    target_link_libraries(
        hello_world_test
        GTest::gtest_main
    )
    include(GoogleTest)
    gtest_discover_tests(hello_world_test)
endif()
