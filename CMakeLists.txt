cmake_minimum_required(VERSION 3.16)
project(xdv-stun VERSION 0.0.1.0 DESCRIPTION "CMake basic template")

# Require C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Force the generator to Ninja
set(CMAKE_GENERATOR "Ninja" CACHE STRING "Set the generator" FORCE)

# Set the output directories to standard locations
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    message("Setting debug compiler flags")
    set(CMAKE_CXX_FLAGS "-Wall -Wno-psabi -g -fms-extensions")
else(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    set(CMAKE_CXX_FLAGS "-Wall -Wno-psabi -O3 -DNDEBUG -fms-extensions")
endif()

# Toggle whether tests get built
set(ENABLE_TESTING True CACHE BOOL "Build test files")
if(${ENABLE_TESTING})
    message("ENABLE_TESTING: ${ENABLE_TESTING} - Testing is enabled!")
    find_package(GTest REQUIRED)
else()
message("ENABLE_TESTING: ${ENABLE_TESTING} - Testing is disabled!")
endif()

# Add project folder
add_subdirectory(stun)
