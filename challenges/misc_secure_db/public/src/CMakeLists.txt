cmake_minimum_required(VERSION 3.21)
project(
        secure_db_task
        VERSION 0.1
        DESCRIPTION "Secure DB"
        LANGUAGES CXX
)

set(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++")

# Warnings config
add_library(warnings_target INTERFACE)
if(MSVC)
    target_compile_options(
            warnings_target
            INTERFACE
            /W4
            /WX "/permissive-"
    )
else()
    target_compile_options(
            warnings_target
            INTERFACE
            -Wall
            -Wextra
            -Wshadow
            -Wnon-virtual-dtor
            -Wold-style-cast
            -Wcast-align
            -Wdouble-promotion
            -Wunused
            -Woverloaded-virtual
            -Wpedantic
            -Wconversion
            -Wsign-conversion
            -Wnull-dereference
            -Werror
    )
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        target_compile_options(
                warnings_target
                INTERFACE
                -Waddress-of-packed-member
                -Wmisleading-indentation
                -Wduplicated-cond
                -Wduplicated-branches
                -Wlogical-op
                -Wuseless-cast
        )
    endif()
endif()

add_library(options_target INTERFACE)
target_compile_features(options_target INTERFACE cxx_std_20)


add_subdirectory(external/tfhe/src)
add_subdirectory(external/spdlog)
add_subdirectory(external/libpaseto)

find_package(Threads)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_subdirectory(proto)

## Target common
add_library(secure_db_task-common)
target_sources(secure_db_task-common
        PRIVATE
        common/db.cpp
        common/db.hpp
)

target_include_directories(secure_db_task-common
        PUBLIC
        common
        external/tfhe/src/include
)

target_link_libraries(secure_db_task-common
        PRIVATE
        options_target

        tfhe-core
        tfhe-fft-spqlios-fma
)

## Target runner

add_executable(secure_db_task-runner)
target_sources(
        secure_db_task-runner
        PRIVATE
        runner/main.cpp
        runner/oracle_service.cpp

        runner/oracle_service.hpp
)

target_link_libraries(
        secure_db_task-runner
        PRIVATE
        options_target

        tfhe-core
        tfhe-fft-spqlios-fma

        ${GRPC_LIBRARIES}
        paseto
        OpenSSL::Crypto

        spdlog::spdlog_header_only

        secure_db_task-common
        secure_db_task-proto
)

target_include_directories(
        secure_db_task-runner
        PRIVATE
        ${CMAKE_BINARY_DIR}/proto
        external/libpaseto/include
        external/tfhe/src/include
)
