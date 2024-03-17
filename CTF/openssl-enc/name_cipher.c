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
 * argv[4] -> file output
 * argv[5] -> cipher_alg
 * save in a buffer in memory the result of encryption
 * key = e6ea3682dea17b2614a7018ee9bdd3b1dba850bedfc770a0a6fb331650d5800d
 * iv = f3a3cd9fa5d18a3d8e6fd3cc35370182c4f51267fc6b5814bf195a7c25d9814b
 * cipher_alg = aes-128-cbc
 * Test with openssl enc -d -aes-128-cbc -in enc.enc -K e6ea3682dea17b2614a7018ee9bdd3b1dba850bedfc770a0a6fb331650d5800d -iv f3a3cd9fa5d18a3d8e6fd3cc35370182c4f51267fc6b5814bf195a7c25d9814b
 */
int main(int argc, char **argv){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc != 6){
        fprintf(stderr, "Invalid parameters. Usage: %s input_file key IV out_file enc_alg\n", argv[0]);
        exit(0);
    }

    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Error opening the input file: %s\n", argv[1]);
        exit(1);
    }

    FILE *f_out;
    if((f_out = fopen(argv[4], "wb")) == NULL){
        fprintf(stderr, "Error opening the input file: %s\n", argv[4]);
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
        sscanf(&argv[3][2*i], "%2hhx", &iv[i]);


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // check NULL
    if(ctx == NULL)
        handle_errors();

    //EVP_CIPHER *cipher = EVP_CIPHER_fetch(ctx, argv[5], NULL);
    EVP_CIPHER *cipher = EVP_get_cipherbyname(argv[5]);
    if(!EVP_CipherInit(ctx, cipher, key, iv, ENCRYPT))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXSIZE];

    int len, ciphertext_len = 0;
    unsigned char ciphertext[MAXSIZE + 16];

    while((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0){

        if(!EVP_CipherUpdate(ctx, ciphertext, &len, buffer, n_read))
            handle_errors();
        ciphertext_len += len;

        if(fwrite(ciphertext, 1, len, f_out) < len){
            fprintf(stderr, "Eroor writing into the output file\n");
            abort();
        }
    }

    if(!EVP_CipherFinal(ctx, ciphertext, &len))
        handle_errors();

    ciphertext_len += len;

    if(fwrite(ciphertext, 1, len, f_out) < len){
        fprintf(stderr, "Eroor writing into the output file\n");
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext length = %d\n", ciphertext_len);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    fclose(f_in);
    fclose(f_out);
    return 0;
}

