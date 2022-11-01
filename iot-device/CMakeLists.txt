cmake_minimum_required(VERSION 3.21)
project(iot-device C)

include_directories(/home/kali/Desktop/emercoin-based-pki-protocol/mbedTLS/build_mbedtls/include)
link_directories(/home/kali/Desktop/emercoin-based-pki-protocol/mbedTLS/build_mbedtls/library)

set(CMAKE_C_STANDARD 99)

add_executable(iot-device main.c initialization.c initialization.h crypto.c crypto.h ownership.c ownership.h utils.c utils.h update.c update.h idevid.h)
target_link_libraries(iot-device mbedtls mbedcrypto mbedx509 tss2-fapi tss2-esys tss2-mu tss2-rc)
