cmake_minimum_required(VERSION 3.18) 

set( CMAKE_CXX_STANDARD 20 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )
set( krypto ${PROJECT_NAME})

project( krypto DESCRIPTION "Cryptography lib in C++ 20" LANGUAGES CXX )

option( krypto_BUILD_TESTS "Enable tests" ON )
option( krypto_BUILD_BENCHMARK "Enable benchmarks" ON )

add_library( ${PROJECT_NAME} INTERFACE )
add_library( ${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME} )

target_include_directories( ${PROJECT_NAME}
    INTERFACE 
        $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )

if ( RADLIB_BUILD_TESTS )
    enable_testing()
    add_subdirectory( test )
endif ( RADLIB_BUILD_TESTS )

if ( RADLIB_BUILD_BENCHMARK )
    add_subdirectory( bench )
endif ( RADLIB_BUILD_BENCHMARK )

