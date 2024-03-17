#include <stdio.h>
#include <string.h>

int main(){

    unsigned char rand1[] = "63-3b-6d-07-65-1a-09-31-7a-4f-b4-aa-ef-3f-7a-55-d0-33-93-52-1e-81-fb-63-11-26-ed-9e-8e-a7-10-f6-63-9d-eb-92-90-eb-76-0b-90-5a-eb-b4-75-d3-a1-cf-d2-91-39-c1-89-32-84-22-12-4e-77-57-4d-25-85-98";
    unsigned char rand2[] = "92-05-d8-b5-fa-85-97-b6-22-f4-bd-26-11-cf-79-8c-db-4a-28-27-bb-d3-31-56-74-16-df-cb-f5-61-a7-9d-18-c2-63-92-f1-cb-c3-6d-2b-77-19-aa-21-07-8e-fe-8b-1a-4f-7d-70-6e-a4-7b-c8-68-30-43-12-50-30-1e";
    unsigned char k1[sizeof(rand1)], k2[sizeof(rand1)], key[sizeof(rand1)];
    unsigned int b1, b2;

    for (int i = 0; i < strlen(rand1); i += 3) {
        sscanf(&rand1[i], "%02x", &b1);
        sscanf(&rand2[i], "%02x", &b2);
        sprintf(&k1[i], "%02x", b1 | b2);
        if (i < strlen(rand1) - 3)
            strcat(k1, "-");
    }

    for (int i = 0; i < strlen(rand1); i += 3) {
        sscanf(&rand1[i], "%02x", &b1);
        sscanf(&rand2[i], "%02x", &b2);
        sprintf(&k2[i], "%02x", b1 & b2);
        if (i < strlen(rand1) - 3)
            strcat(k2, "-");
    }

    for (int i = 0; i < strlen(rand1); i += 3) {
        sscanf(&k1[i], "%02x", &b1);
        sscanf(&k2[i], "%02x", &b2);
        sprintf(&key[i], "%02x", b1 ^ b2);
        if (i < strlen(rand1) - 3)
            strcat(key, "-");
    }

    printf("Key1: %s\nKey2: %s\n\nCRYPTO24{%s}\n", k1, k2, key);
    return 0;
}
