#include <stdio.h>
#include <openssl/bn.h>

int main(){

    char num_string[] = "123456789012345678901234567890123456789012345678901234567890";
    char hex_string[] = "13AAF504E4BC1E62173F87A4378C37B49C8CCFF196CE3F0AD2";
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    BN_dec2bn(&bn1, num_string);
    BN_print_fp(stdout, bn1);
    printf("\n");

    BN_hex2bn(&bn2, hex_string);
    BN_print_fp(stdout, bn2);
    printf("\n");

    if(BN_cmp(bn1, bn2) == 0)
        printf("bn1 and bn2 are equal\n");
    else
        printf("bn1 and bn2 are not equal\n");

    printf("bn1 = %s\n", BN_bn2hex(bn1));
    printf("bn1 = %s\n", BN_bn2dec(bn1));
    BN_free(bn1);
    BN_free(bn2);

    return 0;
}
