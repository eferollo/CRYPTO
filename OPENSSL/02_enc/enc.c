#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt(){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // check NULL
    if(ctx == NULL)
        handle_errors();

    unsigned char key[] = "1234567890abcdef"; //ASCI
    unsigned char iv[] = "abcdef1234567890"; //ASCI

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    unsigned char plaintext[] = "This variable contains the data to encrypt"; //44
    unsigned char ciphertext[48];

    int length;
    int ciphertext_len = 0;
    if(!EVP_CipherUpdate(ctx, ciphertext, &length, plaintext, strlen(plaintext)))
        handle_errors();

    printf("After Update: %d\n", length);
    ciphertext_len += length;

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &length))
        handle_errors();

    printf("After final: %d\n", length);
    ciphertext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

void decrypt(){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL)
        handle_errors();

    unsigned char key[] = "1234567890abcdef"; //ASCI
    unsigned char iv[] = "abcdef1234567890"; //ASCI
    unsigned char ciphertext[] = "13713c9b8081468892c518592730b3496d2c58ed3a9735d90788e7c24e8d324d75f6c9f5c6e43ee7dccad4a3221d697e";

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT))
        handle_errors();

    unsigned char plaintext[strlen(ciphertext) / 2];
    unsigned char ciphertetx_bin[strlen(ciphertext) / 2];

    for(int i = 0; i < strlen(ciphertext)/2; i++)
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertetx_bin[i]);

    int length;
    int plaintext_len = 0;
    if(!EVP_CipherUpdate(ctx, plaintext, &length, ciphertetx_bin, strlen(ciphertext)/2))
        handle_errors();


    printf("After Update: %d\n", length);
    plaintext_len += length;

    if(!EVP_CipherFinal(ctx, plaintext+plaintext_len, &length))
        handle_errors();
    printf("After final: %d\n", length);
    plaintext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    plaintext[plaintext_len] = '\0';
    printf("Plaintext = %s\n", plaintext);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

int main(){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    encrypt();
    decrypt();
    return 0;
}
