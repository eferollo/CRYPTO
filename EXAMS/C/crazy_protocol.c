/**
 * The specification of the CRAZY protocol includes the following operations:
 *
 * 1. Generate two strong random 128-bit integers, name them rand1 and rand2
 *
 * 2. Obtain the first key as
 * k1 = (rand1 + rand2) * (rand1 - rand2) mod 2^128
 *
 * 3. Obtain the second key as
 * k2 = (rand1 * rand2) / (rand1 - rand2) mod 2^128
 *
 * 4. Encrypt k2 using k1 using a stron encryption algorithm (and mode) of your choice
 * call it enc_k2.
 *
 * 5. Generate an RSA keypair with a 2048 bit modulus.
 *
 * 6. Encrypt enc_k2 using the just generated RSA key.
 *
 * Implement in C the protocol steps described above, make the proper decisions when
 * the protocol omits information.
 *
 **/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <string.h>

#define ENCRYPT 1

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (RAND_load_file("/dev/random", 64) != 64) {
        handle_errors();
    }

    /* Compute k1 */
    BIGNUM *rand1 = BN_new();
    BIGNUM *rand2 = BN_new();

    BN_rand(rand1, 128, 0, 1);
    BN_rand(rand2, 128, 0, 1);

    BIGNUM *sum = BN_new();
    BN_add(sum, rand1, rand2);

    BIGNUM *sub = BN_new();
    BN_sub(sub, rand1, rand2);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *mul = BN_new();
    BN_mul(mul, sum, sub, ctx);

    BIGNUM *mod = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *exp = BN_new();

    BN_set_word(base, 2);
    BN_set_word(exp, 128);

    BN_exp(mod, base, exp, ctx);

    BIGNUM *k1 = BN_new();
    BN_mod(k1, mul, mod, ctx);

    /* Compute k2 */
    BN_mul(mul, rand1, rand2, ctx);
    BIGNUM *div = BN_new();
    BN_div(div, NULL, mul, sub, ctx);

    BIGNUM *k2 = BN_new();
    BN_mod(k2, div, mod, ctx);

    BN_free(rand1);
    BN_free(rand2);
    BN_free(sum);
    BN_free(sub);
    BN_free(mul);
    BN_free(div);
    BN_free(mod);
    BN_free(base);
    BN_free(exp);
    BN_CTX_free(ctx);

    /* Encrypt k2 with AES-128-CBC with k1 */
    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();

    char *k1_hex = BN_bn2hex(k1);
    char *k2_hex = BN_bn2hex(k2);
    char k1_bin[strlen(k1_hex)/2], k2_bin[strlen(k2_hex)/2];

    int i;
    for (i = 0; i < strlen(k1_hex)/2; i++) {
        sscanf(&k1_hex[2*i], "%2hhx", &k1_bin[i]);
    }

    for (i = 0; i < strlen(k2_hex)/2; i++) {
        sscanf(&k2_hex[2*i], "%2hhx", &k2_bin[i]);
    }

    if (!EVP_CipherInit(enc_ctx, EVP_aes_128_cbc(), (unsigned char *) k1_bin, NULL, ENCRYPT)) {
        handle_errors();
    }

    unsigned char enc_k2[strlen(k2_hex)+16];
    int update_len, final_len, ciphertext_len = 0;

    if (!EVP_CipherUpdate(enc_ctx, enc_k2, &update_len, (unsigned char *) k2_bin, strlen(k2_hex))) {
        handle_errors();
    }
    ciphertext_len += update_len;

    if(!EVP_CipherFinal_ex(enc_ctx,enc_k2+ciphertext_len,&final_len)) {
        handle_errors();
    }
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(enc_ctx);

    /* Generate RSA keypair and encrypt enc_k2 */
    EVP_PKEY *rsa_keypair = NULL;

    if ((rsa_keypair = EVP_RSA_gen(2048)) == NULL) {
        handle_errors();
    }

    EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    if (EVP_PKEY_encrypt_init(rsa_ctx) <= 0) {
        handle_errors();
    }

    if (EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_errors();
    }

    size_t enc_rsa_k2_len;
    if (EVP_PKEY_encrypt(rsa_ctx, NULL, &enc_rsa_k2_len, enc_k2, ciphertext_len) <= 0) {
        handle_errors();
    }

    unsigned char enc_rsa_k2[enc_rsa_k2_len];
    if (EVP_PKEY_encrypt(rsa_ctx, enc_rsa_k2, &enc_rsa_k2_len, enc_k2, ciphertext_len) <= 0) {
        handle_errors();
    }

    EVP_PKEY_CTX_free(rsa_ctx);
    EVP_PKEY_free(rsa_keypair);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
