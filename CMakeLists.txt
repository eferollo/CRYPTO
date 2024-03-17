cmake_minimum_required(VERSION 3.27)
project(CRYPTO C)

set(CMAKE_C_STANDARD 11)
link_libraries(crypto)
add_executable(01_rand OPENSSL/01_rand/rand.c)

add_executable(02_enc OPENSSL/02_enc/enc.c)
add_executable(02_enc2 OPENSSL/02_enc/enc2.c)
add_executable(02_enc3 OPENSSL/02_enc/enc3.c)

add_executable(03_hash OPENSSL/03_dgst/hash.c)
add_executable(03_hash2 OPENSSL/03_dgst/hash2.c)
add_executable(03_hmac OPENSSL/03_dgst/hmac.c)
add_executable(03_hmac2 OPENSSL/03_dgst/hmac2.c)
add_executable(03_hmac_verify OPENSSL/03_dgst/hmac_verification.c)

add_executable(04_bignum OPENSSL/04_bignum/bignum.c)
add_executable(04_bignum2 OPENSSL/04_bignum/bignum2.c)
add_executable(04_prime OPENSSL/04_bignum/prime.c)

add_executable(05_rsa_keygen OPENSSL/05_asym/rsa_keygen.c)
add_executable(05_rsa_sign OPENSSL/05_asym/rsa_sign.c)

# CTF

add_executable(bytewise_op CTF/openssl-rand/bytewise_op.c)

add_executable(keyed_digest CTF/openssl-dgst/keyed_dgst.c)
add_executable(changeDGST CTF/openssl-dgst/hash3.c)

add_executable(first_hmac CTF/openssl-hmac/firsthmac.c)
add_executable(first_hmac_deprecated CTF/openssl-hmac/firsthmac_deprecated.c)

add_executable(padding CTF/openssl-enc/enc1_nopadding.c)
add_executable(name_cipher CTF/openssl-enc/name_cipher.c)
add_executable(first_dec CTF/openssl-enc/dec1_firstdec.c)
add_executable(guess_algo CTF/openssl-enc/dec1_guessalgo.c)

add_executable(guess_what CTF/openssl-asym/guess_what.c)