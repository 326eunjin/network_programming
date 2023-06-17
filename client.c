#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void errProc(const char *str);
void errPrint(const char *str);

unsigned int calculate_nonce(int start, int end, int difficulty, const char *challenge) {
    for (unsigned int nonce = start; nonce <= end; nonce++) {
        // nonce를 문자열로 변환합니다.
        char nonceStr[20];
        snprintf(nonceStr, sizeof(nonceStr), "%u", nonce);

        // challenge와 nonce를 합친 문자열을 생성합니다.
        char combinedStr[BUFSIZ];
        snprintf(combinedStr, sizeof(combinedStr), "%s%s", challenge, nonceStr);

        // 해시를 계산합니다. (여기에서는 단순히 문자열의 길이를 사용하였습니다.)
        unsigned int hash = strlen(combinedStr);

        // 해시 접두사(prefix)와 일치하는지 확인합니다.
        if (hash <= difficulty) {
            return nonce;
        }
    }

    return -1;  // nonce를 찾지 못한 경우 -1을 반환합니다.
}

int main(int argc, char **argv) {
    int clntSd;
    struct sockaddr_in srvAddr;
    int difficulty;
    char challenge[BUFSIZ];
    unsigned int nonce;

    if (argc != 3) {
        printf("사용법: %s [서버IP] [포트번호] \n", argv[0]);
        exit(1);
    }

    clntSd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clntSd == -1)
        errProc("socket");

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_addr.s_addr = inet_addr(argv[1]);
    srvAddr.sin_port = htons(atoi(argv[2]));

    if (connect(clntSd, (struct sockaddr *)&srvAddr, sizeof(srvAddr)) == -1)
        errProc("connect");

    // 난이도 값을 서버로부터 받음
    read(clntSd, &difficulty, sizeof(difficulty));
    printf("서버로부터 난이도 값(%d)을 받았습니다.\n", difficulty);

    // 도전 값을 서버로부터 받음
    read(clntSd, challenge, BUFSIZ);
    printf("서버로부터 도전 값(%s)을 받았습니다.\n", challenge);

    int num_processes = 4; // 프로세스 수를 설정하세요

    int range = 100000000 / num_processes;  // 범위를 적절히 나누어 줍니다.

    for (int i = 0; i < num_processes; i++) {
        pid_t pid = fork();
        if (pid == -1) {
            errProc("fork");
        } else if (pid == 0) { /* 자식 프로세스 */
            int start = i * range;
            int end = (i + 1) * range - 1;
            nonce = calculate_nonce(start, end, difficulty, challenge);

            printf("프로세스 %d: 범위(%d ~ %d), 계산된 nonce 값(%u)\n", getpid(), start, end, nonce);

            if (write(clntSd, &nonce, sizeof(nonce)) == -1) {
                errPrint("write");
                exit(1);
            }

            close(clntSd);
            exit(0);
        }
    }

    // 부모 프로세스는 자식 프로세스의 실행을 기다림
    for (int i = 0; i < num_processes; i++) {
        wait(NULL);
    }

    close(clntSd);

    return 0;
}

void errProc(const char *str) {
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
    exit(1);
}

void errPrint(const char *str) {
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
}
