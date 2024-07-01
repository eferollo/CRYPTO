/**
 * Alice wants to confidentially send Bob the content of a 1MB file through an insecure
 * channel.
 *
 * Write a program in C, using the OpenSSL library, which Alice can execute to send
 * Bob the file.
 *
 * Assume that:
 * - Bob's public key is stored into the RSA *bob_pubkey data structure;
 * - The file to send is available in the FILE *file_in data structure;
 * - Alice cannot establish TLS channels or resort to other protocols
 * - You have access to a high-level communication primitive that sends and receives data
 * and probably format them (e.g., based on a BIO), so that you don't have to think about
 * the communication issues for this exercise
 *
 **/

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define MAX 16
#define ENCRYPT 1
#define MAX_ENC_LEN 1000000
#define MAX_BUFFER 1024

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void send_bob(void *data)
{
    /* helper function that sends the data over the channel */
}

int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    RSA *bob_pubkey; /* suppose that the pubkey has already been loaded */
    FILE *file_in; /* suppose that the file has been already loaded */

    unsigned char key[MAX];
    unsigned char iv[MAX];

    if (RAND_load_file("/dev/random", 64) != 64) {
        handle_errors();
    }

    if (!RAND_bytes(key, MAX)) {
        handle_errors();
    }

    if (!RAND_bytes(iv, MAX)) {
        handle_errors();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        abort();
    }

    if (!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT)) {
        handle_errors();
    }

    unsigned char ciphertext[MAX_ENC_LEN], buffer[MAX_BUFFER];
    int ciphertext_len = 0, n_read, update_len, final_len;

    while ((n_read = fread(buffer, 1, MAX_BUFFER, file_in)) > 0) {
        if (ciphertext_len > MAX_ENC_LEN - n_read - EVP_CIPHER_CTX_block_size(ctx)) {
            fprintf(stderr, "The file to cipher is too large\n");
            abort();
        }

        if (!EVP_CipherUpdate(ctx, ciphertext+ciphertext_len, &update_len, buffer, n_read)) {
            handle_errors();
        }
        ciphertext_len += update_len;
    }

    if (!EVP_CipherFinal_ex(ctx, ciphertext+ciphertext_len, &final_len)) {
        handle_errors();
    }
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(bob_pubkey)];

    if ((encrypted_data_len =RSA_public_encrypt(strlen(key) + 1,
                                                key,
                                                encrypted_data,
                                                bob_pubkey,
                                                RSA_PKCS1_OAEP_PADDING)) == -1) {
        handle_errors();
    }

    RSA_free(bob_pubkey);

    send_bob(iv);
    send_bob(encrypted_data);
    send_bob(ciphertext);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
