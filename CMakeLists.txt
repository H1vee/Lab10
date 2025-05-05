cmake_minimum_required(VERSION 3.30)
project(untitled1)

set(CMAKE_CXX_STANDARD 20)

add_executable(main main.cpp)
target_link_libraries(main ws2_32 advapi32)
