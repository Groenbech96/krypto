cmake_minimum_required( VERSION ${CMAKE_VERSION} )
set( CMAKE_CXX_STANDARD 20 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

project( krypto_tests DESCRIPTION "krypto tests" LANGUAGES CXX )

find_package(OpenMP REQUIRED)

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

add_subdirectory("${krypto_SOURCE_DIR}/dependencies/googletest" "dependencies/googletest" EXCLUDE_FROM_ALL )

add_executable(krypto_tests
    "test.cpp"
    "test_aes.cpp"
)

target_link_libraries( krypto_tests PRIVATE krypto::krypto gtest gmock gtest_main OpenMP::OpenMP_CXX )

