/*
 * Given the envelop_MAC prototype then implement the following transformation:
 *
 * RSA_encrypt(public_key, SHA_256(SHA_256(message || key)))
 *
 * return 0 in case of success, 1 in case of errors, and the result of the RSA encryption by reference
 */
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylength, char *result)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_MD_CTX *md = EVP_MD_CTX_new();

    if (!EVP_DigestInit(md, EVP_sha256())) {
        handle_errors();
    }

    if (!EVP_DigestUpdate(md, message, message_len)) {
        handle_errors();
    }

    if (!EVP_DigestUpdate(md, key, keylength)) {
        handle_errors();
    }

    unsigned char md_value[EVP_MD_size(EVP_sha256())];
    int md_len;

    if (!EVP_DigestFinal_ex(md, md_value, &md_len)) {
        handle_errors();
    }

    EVP_MD_CTX_reset(md);

    if (!EVP_DigestInit(md, EVP_sha256())) {
        handle_errors();
    }

    if (!EVP_DigestUpdate(md, md_value, md_len)) {
        handle_errors();
    }

    unsigned char md_final[EVP_MD_size(EVP_sha256())];
    int md_final_len;

    if (!EVP_DigestFinal_ex(md, md_final, &md_final_len)) {
        handle_errors();
    }

    EVP_MD_CTX_free(md);

    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(rsa_keypair)];

    encrypted_data_len = RSA_public_encrypt(strlen(md_final)+1,
                                            md_final,
                                            encrypted_data,
                                            rsa_keypair,
                                            RSA_PKCS1_OAEP_PADDING);
    if(encrypted_data_len == -1) {
        handle_errors();
        return 1;
    }

    memcpy(result, encrypted_data, encrypted_data_len);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
