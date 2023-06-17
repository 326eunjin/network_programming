#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>

#define MAX_PROCESSES 4

typedef struct {
    unsigned char input[256];
    unsigned int difficulty;
    unsigned int startNonce;
    unsigned int endNonce;
} PowTask;

void calculatePoW(const unsigned char *input, unsigned int difficulty, unsigned int startNonce, unsigned int endNonce) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char target[SHA256_DIGEST_LENGTH];
    unsigned int nonce;

    // Set the target hash based on the difficulty
    memset(target, 0xFF, sizeof(target));
    for (unsigned int i = 0; i < difficulty; i++) {
        target[i / 8] &= ~(1 << (i % 8));
    }

    // Perform the proof of work calculation
    for (nonce = startNonce; nonce <= endNonce; nonce++) {
        unsigned char data[256 + sizeof(nonce)];
        memcpy(data, input, strlen((char*)input));
        memcpy(data + strlen((char*)input), &nonce, sizeof(nonce));
        SHA256(data, strlen((char*)input) + sizeof(nonce), hash);

        if (memcmp(hash, target, difficulty / 8) == 0) {
            printf("PoW found! Nonce: %u\n", nonce);
            break;
        }
    }
}

int main() {
    unsigned char input[256];
    unsigned int difficulty;

    printf("Enter the input: ");
    fgets((char*)input, sizeof(input), stdin);
    input[strcspn((char*)input, "\n")] = 0;

    printf("Enter the difficulty: ");
    scanf("%u", &difficulty);

    // Calculate the workload for each process
    unsigned int range = UINT_MAX / MAX_PROCESSES;
    PowTask tasks[MAX_PROCESSES];
    for (int i = 0; i < MAX_PROCESSES; i++) {
        tasks[i].startNonce = i * range;
        tasks[i].endNonce = (i + 1) * range - 1;
        tasks[i].difficulty = difficulty;
        memcpy(tasks[i].input, input, sizeof(input));
    }

    // Fork multiple processes and perform PoW calculation in parallel
    for (int i = 0; i < MAX_PROCESSES; i++) {
        pid_t pid = fork();

        if (pid == 0) {  // Child process
            calculatePoW(tasks[i].input, tasks[i].difficulty, tasks[i].startNonce, tasks[i].endNonce);
            exit(0);
        } else if (pid < 0) {  // Forking error
            fprintf(stderr, "Forking error\n");
            exit(1);
        }
    }

    // Wait for all child processes to finish
    for (int i = 0; i < MAX_PROCESSES; i++) {
        wait(NULL);
    }

    return 0;
}
