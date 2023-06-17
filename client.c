#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

void errProc(const char *str);
void errPrint(const char *str);
unsigned int calculateNonce(unsigned int start, unsigned int end, int difficulty, const char *challenge);

int main(int argc, char **argv) {
    int srvSd;
    struct sockaddr_in srvAddr;
    int strLen;
    char rBuff[BUFSIZ];
    int difficulty;
    char challenge[BUFSIZ];
    unsigned int nonce; // Changed nonce type to unsigned int
    int numProcesses = 4; // Number of child processes to create

    if (argc != 3) {
        printf("사용법: %s [서버IP] [포트번호]\n", argv[0]);
        exit(1);
    }

    printf("클라이언트 시작...\n");

    srvSd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srvSd == -1)
        errProc("socket");

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_addr.s_addr = inet_addr(argv[1]);
    srvAddr.sin_port = htons(atoi(argv[2]));

    if (connect(srvSd, (struct sockaddr *)&srvAddr, sizeof(srvAddr)) == -1)
        errProc("connect");

    // 난이도 값 수신
    read(srvSd, &difficulty, sizeof(difficulty));
    printf("난이도: %d\n", difficulty);

    // 도전 값 수신
    read(srvSd, challenge, sizeof(challenge));
    printf("도전 값: %s\n", challenge);

    // Fork child processes
    for (int i = 0; i < numProcesses; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            // Child process
            unsigned int start = UINT_MAX / numProcesses * i;
            unsigned int end = UINT_MAX / numProcesses * (i + 1) - 1;

            nonce = calculateNonce(start, end, difficulty, challenge);

            // nonce 값 전송
            write(srvSd, &nonce, sizeof(nonce));
            printf("Child process %d: Nonce %u 값을 서버에 전송하였습니다.\n", getpid(), nonce);

            close(srvSd);
            exit(0);
        } else if (pid < 0) {
            // Error occurred
            errProc("fork");
        }
    }

    // Parent process
    for (int i = 0; i < numProcesses; i++) {
        wait(NULL);
    }

    printf("모든 child process가 완료되었습니다.\n");
    close(srvSd);

    return 0;
}

void errProc(const char *str) {
    fprintf(stderr, "%s: %s\n", str, strerror(errno));
    exit(1);
}

void errPrint(const char *str) {
    fprintf(stderr, "%s: %s\n", str, strerror(errno));
}

unsigned int calculateNonce(unsigned int start, unsigned int end, int difficulty, const char *challenge) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hexString[SHA256_DIGEST_LENGTH * 2 + 1];
    unsigned int nonce;

    for (nonce = start; nonce <= end; nonce++) {
        // Convert nonce to string representation
        char nonceString[sizeof(nonce) * 2 + 1];
        sprintf(nonceString, "%08x", nonce);

        // Concatenate the challenge and nonce
        char data[BUFSIZ];
        snprintf(data, BUFSIZ, "%s%s", challenge, nonceString);

        // Calculate the SHA256 hash
        SHA256((unsigned char *)data, strlen(data), hash);

        // Convert the hash to a hex string
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(&hexString[i * 2], "%02x", hash[i]);
        }
        hexString[SHA256_DIGEST_LENGTH * 2] = '\0';

        // Check if the hash meets the difficulty requirement
        int match = 1;
        for (int i = 0; i < difficulty; i++) {
            if (hexString[i] != '0') {
                match = 0;
                break;
            }
        }

        if (match) {
            printf("Child process %d: Nonce found: %u\n", getpid(), nonce);
            return nonce;
        }
    }

    printf("Child process %d: Nonce not found within the specified range.\n", getpid());
    return 0;
}
