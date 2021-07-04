cmake_minimum_required(VERSION 3.19)
project(scan_util_client_server)

set(CMAKE_CXX_STANDARD 20)

add_executable(scan_service server.cpp)
add_executable(scan_util client.cpp)
