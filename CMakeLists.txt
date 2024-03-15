cmake_minimum_required(VERSION 3.27)
project(CRYPTO C)

set(CMAKE_C_STANDARD 11)
link_libraries(crypto)
add_executable(01_rand OPENSSL/01_rand/rand.c)
add_executable(02_enc OPENSSL/02_enc/enc.c)
add_executable(02_enc2 OPENSSL/02_enc/enc2.c)
add_executable(02_enc3 OPENSSL/02_enc/enc3.c)
