cmake_minimum_required( VERSION ${CMAKE_VERSION} )
set( CMAKE_CXX_STANDARD 20 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

project( krypto_bench DESCRIPTION "krypto benchmark" LANGUAGES CXX )

find_package(OpenMP REQUIRED)

# Prevent overriding the parent project's compiler/linker
# settings on Windows

add_subdirectory("${krypto_SOURCE_DIR}/dependencies/googlebench" "dependencies/googlebench" EXCLUDE_FROM_ALL )

add_executable(krypto_bench
    "bench_aes.cpp"
)

target_link_libraries( krypto_bench PRIVATE krypto::krypto benchmark OpenMP::OpenMP_CXX )

