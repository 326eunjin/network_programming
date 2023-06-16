#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void errProc(const char *str);
void errPrint(const char *str);
void child_handler(int signum);

int main(int argc, char **argv) {
    int srvSd, clntSd;
    struct sockaddr_in srvAddr, clntAddr;
    int clntAddrLen, strLen;
    char rBuff[BUFSIZ];
    pid_t pid;
    struct sigaction sa;
    int difficulty = 7; // 난이도 값을 나타내는 변수 (정수)
    char *challenge = "0000000"; // 도전 값을 나타내는 변수 (문자열)

    if (argc != 2) {
        printf("사용법: %s [포트번호] \n", argv[0]);
        exit(1);
    }
    printf("서버 시작...\n");

    srvSd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srvSd == -1)
        errProc("socket");

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(atoi(argv[1]));

    if (bind(srvSd, (struct sockaddr *)&srvAddr, sizeof(srvAddr)) == -1)
        errProc("bind");
    if (listen(srvSd, 5) < 0)
        errProc("listen");

    clntAddrLen = sizeof(clntAddr);

    // 핸들러 설정
    sa.sa_handler = child_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    while (1) {
        clntSd = accept(srvSd, (struct sockaddr *)&clntAddr, &clntAddrLen);
        if (clntSd == -1) {
            errPrint("accept");
            continue;
        }
        printf("클라이언트 %s:%d가 연결되었습니다...\n", inet_ntoa(clntAddr.sin_addr),
               ntohs(clntAddr.sin_port));
        pid = fork();
        if (pid == 0) { /* 자식 프로세스 */
            close(srvSd);
            // 난이도를 클라이언트에게 전송
            write(clntSd, &difficulty, sizeof(difficulty));
            // 도전 값을 클라이언트에게 전송
            write(clntSd, challenge, strlen(challenge));

            printf("난이도와 도전 값을 클라이언트에게 전송하였습니다.\n");

            close(clntSd);
            return 0;
        } else if (pid == -1)
            errProc("fork");
        else { /* 부모 프로세스 */
            close(clntSd);
        }
    }
    close(srvSd);
    return 0;
}

void errProc(const char *str) {
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
    exit(1);
}

void errPrint(const char *str) {
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
}

void child_handler(int signo) {
    pid_t pid;
    int stat;
    // 자식 프로세스 상태 반환
    while ((pid = wait(&stat)) > 0)
        printf("자식/클라이언트(%d)가 종료되었습니다.\n", pid);
    return;
}