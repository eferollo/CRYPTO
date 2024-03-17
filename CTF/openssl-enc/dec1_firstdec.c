#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

int main() {

    // every ciphertext decoded from base64 -> echo 'jyS3NIBqen2CWpDI2jkSu+z93NkDbWkUMitg2Q==' | base64 -d | xxd -p
    unsigned char key_hex[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    unsigned char iv_hex[] = "11111111111111112222222222222222";
    const char *ciphertext_hex = "8f24b734806a7a7d825a90c8da3912bbecfddcd9036d6914322b60d9";

    unsigned char key[strlen(key_hex)/2];
    unsigned char iv[strlen(iv_hex)/2];

    for(int i = 0; i < strlen(key_hex)/2; i++)
        sscanf(&key_hex[i*2], "%2hhx", &key[i]);

    for(int i = 0; i < strlen(iv_hex)/2; i++)
        sscanf(&iv_hex[i*2], "%2hhx", &iv[i]);

    // Convert hexstring into bytes
    int ciphertext_len = strlen(ciphertext_hex) / 2;
    unsigned char ciphertext_binary[ciphertext_len];
    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(&ciphertext_hex[2 * i], "%2hhx", &ciphertext_binary[i]);
    }

    unsigned char decrypted[ciphertext_len]; // May be larger than needed due to padding

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_chacha20(), key, iv, DECRYPT);

    int update_len, final_len;
    int decrypted_len = 0;
    EVP_CipherUpdate(ctx, decrypted, &update_len, ciphertext_binary, ciphertext_len);
    decrypted_len += update_len;

    EVP_CipherFinal_ex(ctx, decrypted + decrypted_len, &final_len);
    decrypted_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Algorithm: %s\n", EVP_CIPHER_name(EVP_chacha20()));
    printf("Plaintext lenght = %d\n",decrypted_len);
    for(int i = 0; i < decrypted_len; i++)
        printf("%2x", decrypted[i]);
    printf("\n");
    for (int i = 0; i < decrypted_len; i++)
        printf("%c", decrypted[i]);
    printf("\n\n");


    return 0;
}
