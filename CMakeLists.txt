cmake_minimum_required(VERSION 3.19)
project(scan_util_client_server)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS -lpthread)

add_subdirectory(scan_service/)
add_subdirectory(scan_util/)
