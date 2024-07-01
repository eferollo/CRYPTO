#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define LEN 32

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    unsigned char r1[LEN], r2[LEN], key_simm[LEN];
    int i;

    if (RAND_load_file("/dev/random", 64) != 64) {
        handle_errors();
    }

    if (!RAND_bytes(r1, LEN)) {
        handle_errors();
    }

    if (!RAND_bytes(r2, LEN)) {
        handle_errors();
    }

    for (i = 0; i < LEN; i++) {
        key_simm[i] = r1[i]^r2[i];
    }

    RSA *rsa_keypair = RSA_new();
    BIGNUM *bne = BN_new();

    if (!BN_set_word(bne, RSA_F4)) {
        handle_errors();
    }

    if (!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL)) {
        handle_errors();
    }

    if (!PEM_write_RSAPrivateKey(stdout, rsa_keypair, EVP_aes_256_cbc(), key_simm, strlen(key_simm), NULL, NULL)) {
        handle_errors();
    }

    RSA_free(rsa_keypair);
    BN_free(bne);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
