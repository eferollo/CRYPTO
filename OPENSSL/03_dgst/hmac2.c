#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h> //deprecated

#define MAXBUF 1024

/*
 * First parameter is the name of the file to hash
 */

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){

    if(argc != 2){
        fprintf(stderr,"Invalid parameters num. Usage: %s string_to_hash\n", argv[0]);
        exit(-1);
    }

    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        printf("Couldn't open the file\n");
        exit(1);
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    unsigned char key[] = "1234567887654321"; // ASCI (we should not use unsigned char for keys)
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));

    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha1(), NULL, hmac_key))
        handle_errors();

    unsigned char buffer[MAXBUF];
    size_t n_read;
    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    unsigned char hmac_value[EVP_MD_size(EVP_sha1())];
    size_t hmac_len;

    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();
    EVP_MD_CTX_free(hmac_ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The HMAC is: ");
    for(int i = 0; i < hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");
    return 0;
}

