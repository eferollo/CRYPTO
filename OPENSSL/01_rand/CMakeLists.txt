cmake_minimum_required(VERSION 3.27)
project(01_rand C)

set(CMAKE_C_STANDARD 11)
link_libraries(crypto)
add_executable(01_rand main.c)
