cmake_minimum_required(VERSION 3.10.2)
project("nativessl")

set(NATIVE_SRC native-lib.cpp)

add_library(native-lib SHARED ${NATIVE_SRC})

target_include_directories(native-lib PRIVATE
        ${CMAKE_SOURCE_DIR}/openssl
)

add_library(ssl STATIC IMPORTED)
set_target_properties(ssl PROPERTIES
        IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/lib/arm64-v8a/libssl.a
)

add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES
        IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/lib/arm64-v8a/libcrypto.a
)

find_library(log-lib log)

target_link_libraries(native-lib
        ssl
        crypto
        ${log-lib}
)