/**
    Sketch the Diffie-Hellman key agreement protocol in C using the OpenSSl library.
    Imagine you have a client CARL that starts communicating with a server SARA.
    CARL initiates the communication and proposes the public parameters.

    Assume you have access to a set of high-level communication primitives that allow
    you to send and receive big numbers and to properly format them (e.g., based on a BIO)
    so that you don't have to think about the communication issues for this exercise.

    void send_to_sara(BIGNUM b)
    BIGNUM receive_from_sara()
    void send_to_carl(BIGNUM b)
    BIGNUM receive_from_carl()

    Finally answer the following question: what CARL and SARA have to do if they want
    to generate an AES-256 key?
*/

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void send_to_sara(BIGNUM *b);
BIGNUM *receive_from_sara();
void send_to_carl(BIGNUM *b);
BIGNUM *receive_from_carl();

/*
 * 1. Carl generates p and g
 * 2. Carl computes A=g^x mod p and send A,p,g
 * 3. Sara computes B=g^y mod p and send B
 * 4. Carl computes B^x mod p -> key
 * 5. Sara computes A^y mod p -> key
 */
int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (RAND_load_file("/dev/random", 64) != 64) {
        handle_errors();
    }

    if (!BN_generate_prime_ex(p, 32*8, 0, NULL, NULL, NULL)) {
        handle_errors();
    }

    if (!BN_generate_prime_ex(g, 32*8, 0, NULL, NULL, NULL)) {
        handle_errors();
    }

    BIGNUM *x = BN_new();
    BN_rand(x, 31*8, 0, 1);

    BIGNUM *A = BN_new();

    if (!BN_mod_exp(A, g, x, p, ctx)) {
        handle_errors();
    }

    send_to_sara(p);
    send_to_sara(g);
    send_to_sara(A);

    BIGNUM *B = receive_from_sara();

    BIGNUM *key = BN_new();
    if (!BN_mod_exp(key, B, x, p, ctx)) {
        handle_errors();
    }

    BN_free(A);
    BN_free(B);
    BN_free(p);
    BN_free(g);
    BN_free(x);

    BN_CTX_free(ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;
}
