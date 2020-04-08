cmake_minimum_required(VERSION 3.16)
project(tlslite C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(src)

add_executable(test tlsmain.c)
target_link_libraries(test PRIVATE sockets tls)
