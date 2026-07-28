cmake_minimum_required(VERSION 3.22)
project(test-openssl-conan C)

find_package(OpenSSL REQUIRED)

add_executable(tls tls.c)
target_link_libraries(tls PRIVATE OpenSSL::Crypto)

add_custom_target(run-tls
    COMMAND tls
    DEPENDS tls
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
)
