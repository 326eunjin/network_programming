#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/wait.h>

#define MAX_PROCESSES 8

void calculate_hash(const char *input, unsigned int nonce, unsigned char *hash) {
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

void find_nonce(const int write_fd, const char *input, const int difficulty, const unsigned int start_nonce, const unsigned int end_nonce) {
    unsigned int nonce = start_nonce;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    while (nonce <= end_nonce) {
        calculate_hash(input, nonce, hash);

        if (check_difficulty(hash, difficulty)) {
            write(write_fd, &nonce, sizeof(unsigned int)); // Write the nonce to the pipe
            close(write_fd);
            return;
        }

        nonce++;
    }

    close(write_fd);
}

int main() {
    int difficulty;
    char input[256];
    unsigned int nonce;

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
    int pipes[MAX_PROCESSES][2];

    printf("Difficulty: %d\n", difficulty);
    printf("Challenge: %s\n", input);
    printf("Number of processes: %u\n", num_processes);

    for (unsigned int i = 0; i < num_processes; i++) {
        if (pipe(pipes[i]) == -1) {
            fprintf(stderr, "Failed to create pipe.\n");
            return 1;
        }

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
            close(pipes[i][0]); // Close the read end of the pipe in the child process
            find_nonce(pipes[i][1], input, difficulty, start_nonce, end_nonce);
            exit(0);
        } else {
            close(pipes[i][1]); // Close the write end of the pipe in the parent process
            pids[i] = pid;
        }
    }

    for (unsigned int i = 0; i < num_processes; i++) {
        if (read(pipes[i][0], &nonce, sizeof(unsigned int)) != -1) {
            break;
        }
    }

    for (unsigned int i = 0; i < num_processes; i++) {
        close(pipes[i][0]); // Close the read end of the pipe in the parent process
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    calculate_hash(input, nonce, hash);

    printf("Nonce: %u\n", nonce);
    printf("Hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
