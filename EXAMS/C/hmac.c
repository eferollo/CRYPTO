/**
 * The program has to check if the computed mac equals
 * the one passed as the second parameter of the command line
 * the program return 0 if the comparison is successful.
 * The hmac key is stored on the file /keys/hmac_key
 * The mac needs to be computed using hmac-sha256
 *
 **/

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,"Invalid parameters. Usage: %s filename HMAC\n",argv[0]);
        exit(1);
    }

    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }

    /* Load the HMAC key */
    FILE *f_key;
    if ((f_key = fopen("/keys/hmac_key", "r")) == NULL) {
        fprintf(stderr,"Couldn't open the key file, try again\n");
        exit(1);
    }

    /* Read the key with a buffer from the key file */
    unsigned char key_buffer[MAXBUF];
    if (fread(key_buffer, 1, MAXBUF, f_key) < 0) {
        exit(1);
    }
    fclose(f_key);

    /* Convert and store the key from hex to binary */
    unsigned char key[strlen(key_buffer)/2];
    int i;
    for (i = 0; i < strlen(key_buffer)/2; i++) {
        sscanf(&key_buffer[2*i], "%2hhx", &key[i]);
    }

    /* Compute the HMAC of the plaintext and initialize the EVP_PKEY */
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    EVP_PKEY *hkey;
    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 32);

    if (!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey)) {
        handle_errors();
    }

    size_t n;
    unsigned char buffer[MAXBUF];
    while ((n = fread(buffer, 1, MAXBUF, f_in)) > 0) {
        if (!EVP_DigestSignUpdate(hmac_ctx, buffer, n)) {
            handle_errors();
        }
    }
    fclose(f_in);

    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
    size_t hmac_len = EVP_MD_size(EVP_sha256());

    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len)) {
        handle_errors();
    }

    EVP_MD_CTX_free(hmac_ctx);

    /* Verification of the computed HMAC against the HMAC loaded from cli */

    /* Load the HMAC to be checked and convert it from hex to binary */
    unsigned char hmac_tocheck[strlen(argv[2])/2];
    for (i = 0, i < strlen(argv[2])/2; i++) {
        sscanf(&argv[2][2*i], "%2hhx", &hmac_tocheck[i]);
    }

    if ((hmac_len == (strlen(argv[2])/2)) && (CRYPTO_memcmp(hmac_tocheck, hmac_value, hmac_len) == 0)) {
        return 0;
    }

    return -1;
}
