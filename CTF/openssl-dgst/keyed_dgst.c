#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#define MAXBUF 1024

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

    unsigned char secret[] = "this_is_my_secret";
    EVP_MD_CTX *md;
    md = EVP_MD_CTX_new();

    if(md == NULL)
        handle_errors();

    if(!EVP_DigestInit(md, EVP_sha512()))
        handle_errors();

    unsigned char buffer[MAXBUF];
    int n_read;

    EVP_DigestUpdate(md, secret, strlen(secret));
    while( (n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }
    EVP_DigestUpdate(md, secret, strlen(secret));

    unsigned char md_value[EVP_MD_size(EVP_sha512())];
    int md_len;

    if(!EVP_DigestFinal_ex(md, md_value, &md_len))
        handle_errors();

    EVP_MD_CTX_free(md);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The digest is: ");
    for(int i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");
    return 0;
}
