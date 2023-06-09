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
#include <time.h>

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
    int difficulty = 6; // 난이도 값을 나타내는 변수 (정수)
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

    int num_clients = 2; // 클라이언트 수
    unsigned int nonce_received = 0;
    unsigned int nonce = 0;
    double start_time, end_time, elapsed_time;
    int nonce_received_count = 0; // nonce 값을 받은 클라이언트 수

    while (nonce_received_count < num_clients) {
        clntSd = accept(srvSd, (struct sockaddr *)&clntAddr, &clntAddrLen);
        if (clntSd == -1) {
            errPrint("accept");
            continue;
        }
        printf("Working Server %s:%d가 연결되었습니다...\n", inet_ntoa(clntAddr.sin_addr),
               ntohs(clntAddr.sin_port));
        pid = fork();
        if (pid == 0) { /* 자식 프로세스 */
            close(srvSd);
            // 난이도를 클라이언트에게 전송
            write(clntSd, &difficulty, sizeof(difficulty));
            // 도전 값을 클라이언트에게 전송
            write(clntSd, challenge, strlen(challenge));

            printf("난이도와 도전 값을 Working Server에 전송하였습니다.\n");

            // 다른 클라이언트가 이미 nonce 값을 보낸 경우 예외 처리
            if (nonce_received > 0) {
                printf("다른 클라이언트가 이미 nonce 값을 보냈습니다. 연결 종료.\n");
                close(clntSd);
                return 0;
            }

            // nonce 값을 클라이언트로부터 받음
            read(clntSd, &nonce_received, sizeof(nonce_received));

            // 클라이언트로부터 받은 nonce 값 출력
            printf("클라이언트로부터 받은 nonce 값: %d\n", nonce_received);

            close(clntSd);

            // nonce 값을 받았을 때 시간 측정 종료
            if (nonce_received > 0 && nonce == 0) {
                nonce = nonce_received;
                end_time = clock();
                elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

                printf("nonce 값(%d)에 대한 소요 시간: %f 초\n", nonce, elapsed_time);

                // 프로그램 종료
                return 0;
            }

            // nonce 값을 받은 클라이언트 수 증가
            nonce_received_count++;

            return 0;
        } else if (pid == -1)
            errProc("fork");
        else { /* 부모 프로세스 */
            close(clntSd);

            // nonce 값을 받았을 때 시간 측정 시작
            if (nonce_received > 0 && nonce == 0) {
                nonce = nonce_received;
                start_time = clock();
            }
        }
    }

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
        printf("Working Server(%d)가 종료되었습니다.\n", pid);
    return;
}
