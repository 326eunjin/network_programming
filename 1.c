#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

int main() {
    unsigned char input[] = "201928717118523";
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(input, strlen((char*)input), hash);

    printf("hash(201928713221225469): ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
