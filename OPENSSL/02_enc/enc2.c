#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAXSIZE 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * argv[1] -> input file
 * argv[2] -> key (hexstring)
 * argv[3] -> IV (hexstring)
 * save in a buffer in memory the result of encryption
 */
int main(int argc, char **argv){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc != 4){
        fprintf(stderr, "Invalid parameters. Usage: %s input_file key IV\n", argv[0]);
        exit(0);
    }

    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Error opening the input file: %s\n", argv[1]);
        exit(1);
    }

    if(strlen(argv[2])/2 != 32){
        fprintf(stderr, "Wrong key length: %s\n", argv[2]);
        exit(1);
    }

    unsigned char key[strlen(argv[2])/2];
    for(int i = 0; i < strlen(argv[2])/2; i++)
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);

    if(strlen(argv[3])/2 != 32){
        fprintf(stderr, "Wrong IV length: %s\n", argv[3]);
        exit(1);
    }

    unsigned char iv[strlen(argv[3])/2];
    for(int i = 0; i < strlen(argv[3])/2; i++)
        sscanf(&argv[2][2*i], "%2hhx", &iv[i]);


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // check NULL
    if(ctx == NULL)
        handle_errors();

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXSIZE];

    unsigned char ciphertext[100 * MAXSIZE];

    int len, ciphertext_len = 0;

    while((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0){

        // if yu risk to overflow the ciphertext you exit before with an error
        // n_read + 1 block > left in ciphertext (MAX - ciphertext_len)
        if(ciphertext_len > 100*MAXSIZE - n_read - EVP_CIPHER_CTX_block_size(ctx)){
            fprintf(stderr, "The file to cipher is larger than expected\n");
            exit(1);
        }

        if(!EVP_CipherUpdate(ctx, ciphertext+ciphertext_len, &len, buffer, n_read))
            handle_errors();
        ciphertext_len += len;
    }

    if(!EVP_CipherFinal(ctx, ciphertext + ciphertext_len, &len))
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext length = %d\n", ciphertext_len);
    for(int i = 0; i< ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    fclose(f_in);

    return 0;
}
