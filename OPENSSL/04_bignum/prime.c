#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    char num_string[] = "123456789012345678901234567890123456789012345678901234567890";
    char hex_string[] = "13AAF504E4BC1E62173F87A4378C37B49C8CCFF196CE3F0AD2";

    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();


    // BN_generate_prime_ex2() + pass also a context
    /* a prime number is safe if (p-1)/2 is also a prime
     * add, rem -->? p
     * p % add == rem
     * if rem is NULL --> rem=1
     * if rem is NULL and safe is true ->> rem = 3 add must be multiple of 4
     */
    if(!BN_generate_prime_ex(prime1, 1024, 0, NULL, NULL, NULL))
        handle_errors();

    BN_print_fp(stdout, prime1);
    puts("");

    if(BN_is_prime_ex(prime1, 16, NULL, NULL))
        printf("It's a prime\n");
    else
        printf("It's not a prime\n");
    // BN_check_prime(prime1, ctx, cb)

    BN_set_word(prime2, 16);
    if(BN_is_prime_ex(prime2, 16, NULL, NULL))
        printf("It's a prime\n");
    else
        printf("It's not a prime\n");

    printf("bits prime1: %d\n", BN_num_bytes(prime1));
    printf("bits prime2: %d\n", BN_num_bytes(prime2));

    BN_free(prime1);
    BN_free(prime2);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
