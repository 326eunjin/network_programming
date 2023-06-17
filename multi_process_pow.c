#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/wait.h>

#define MAX_PROCESSES 8

void calculate_hash(const char *input, const unsigned int nonce, unsigned char *hash) {
    char data[256];
    snprintf(data, sizeof(data), "%s%u", input, nonce);

    SHA256((unsigned char *)data, strlen(data), hash);
}

int check_difficulty(unsigned char *hash, const int difficulty) {
    int count = 0;
    for (int i = 0; i < difficulty / 2; i++) {
        if (hash[i] == 0) {
            count += 2;
        } else {
            break;
        }
    }

    if (difficulty % 2 == 1 && (hash[difficulty / 2] & 0xF0) == 0) {
        count++;
    }

    return count >= difficulty;
}

void find_nonce(const char *input, const int difficulty, const unsigned int start_nonce, const unsigned int end_nonce) {
    unsigned int nonce = start_nonce;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    while (nonce <= end_nonce) {
        calculate_hash(input, nonce, hash);

        if (check_difficulty(hash, difficulty)) {
            printf("Hash: ");
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                printf("%02x", hash[i]);
            }
            printf("\nNonce: %u\n", nonce);
            exit(0);
        }

        nonce++;
    }
}

int main() {
    int difficulty;
    char input[256];

    printf("Enter the difficulty: ");
    scanf("%d", &difficulty);

    printf("Enter the challenge: ");
    scanf("%s", input);

    unsigned int num_processes;
    printf("Enter the number of processes (1-%d): ", MAX_PROCESSES);
    scanf("%u", &num_processes);

    if (num_processes > MAX_PROCESSES) {
        printf("Invalid number of processes. Setting to the maximum value (%d).\n", MAX_PROCESSES);
        num_processes = MAX_PROCESSES;
    }

    unsigned int num_nonce_per_process = (UINT32_MAX + 1) / num_processes;
    pid_t pids[MAX_PROCESSES];

    printf("Difficulty: %d\n", difficulty);
    printf("Challenge: %s\n", input);
    printf("Number of processes: %u\n", num_processes);

    for (unsigned int i = 0; i < num_processes; i++) {
        unsigned int start_nonce = i * num_nonce_per_process;
        unsigned int end_nonce = (i + 1) * num_nonce_per_process - 1;

        if (i == num_processes - 1) {
            end_nonce = UINT32_MAX;
        }

        pid_t pid = fork();

        if (pid < 0) {
            fprintf(stderr, "Fork failed.\n");
            return 1;
        } else if (pid == 0) {
            find_nonce(input, difficulty, start_nonce, end_nonce);
            exit(0);
        } else {
            pids[i] = pid;
        }
    }

    for (unsigned int i = 0; i < num_processes; i++) {
        waitpid(pids[i], NULL, 0);
    }

    return 0;
}
