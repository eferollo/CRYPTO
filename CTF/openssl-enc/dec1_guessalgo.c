#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

int main() {

    // every ciphertext decoded from base64
    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[] = "0123456789ABCDEF";
    const char *ciphertext_hex = "65927e04a24d7695c0da3697f1983922d46895ad7c862f79306f1f03ff513ef8";

    // Convert hexstring into bytes
    int ciphertext_len = strlen(ciphertext_hex) / 2;
    unsigned char ciphertext_binary[ciphertext_len];
    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(&ciphertext_hex[2 * i], "%2hhx", &ciphertext_binary[i]);
    }

    unsigned char decrypted[ciphertext_len]; // May be larger than needed due to padding

    const EVP_CIPHER *cipher;
    const EVP_CIPHER *ciphers[] = {
            EVP_aes_128_cbc(), EVP_aes_128_cfb(), EVP_aes_128_cfb1(), EVP_aes_128_cfb8(),
            EVP_aes_128_ctr(), EVP_aes_128_ecb(), EVP_aes_128_ofb(),
            EVP_camellia_128_cbc(), EVP_camellia_128_cfb(), EVP_camellia_128_cfb1(), EVP_camellia_128_cfb8(),
            EVP_camellia_128_ctr(), EVP_camellia_128_ecb(), EVP_camellia_128_ofb(),
            EVP_aria_128_cbc(), EVP_aria_128_cfb(), EVP_aria_128_cfb1(), EVP_aria_128_cfb8(),
            EVP_aria_128_ctr(), EVP_aria_128_ecb(), EVP_aria_128_ofb(),NULL
    };


    for (int i = 0; ciphers[i] != NULL; i++) {
        cipher = ciphers[i];
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit(ctx, cipher, key, iv, DECRYPT);

        int update_len, final_len;
        int decrypted_len = 0;
        EVP_CipherUpdate(ctx, decrypted, &update_len, ciphertext_binary, ciphertext_len);
        decrypted_len += update_len;

        EVP_CipherFinal_ex(ctx, decrypted + decrypted_len, &final_len);
        decrypted_len += final_len;

        EVP_CIPHER_CTX_free(ctx);

        printf("Algorithm: %s\n", EVP_CIPHER_name(cipher));
        printf("Plaintext lenght = %d\n",decrypted_len);
        for(int i = 0; i < decrypted_len; i++)
            printf("%2x", decrypted[i]);
        printf("\n");
        for (int i = 0; i < decrypted_len; i++)
            printf("%c", decrypted[i]);
        printf("\n\n");
    }

    return 0;
}