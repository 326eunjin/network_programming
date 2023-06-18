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

int main(int argc, char **argv) {
    int sock;
    struct sockaddr_in servAddr;
    int strLen;
    int difficulty;
    char challenge[BUFSIZ];
    unsigned int nonce;

    if (argc != 3) {
        printf("사용법: %s [서버 IP 주소] [포트번호]\n", argv[0]);
        exit(1);
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
        errProc("socket");

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(argv[1]);
    servAddr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1)
        errProc("connect");

    // 난이도 값을 서버로부터 수신
    if (read(sock, &difficulty, sizeof(difficulty)) == -1)
        errProc("read");

    // 도전 값을 서버로부터 수신
    if (read(sock, challenge, BUFSIZ) == -1)
        errProc("read");

    printf("난이도: %d, 도전 값: %s\n", difficulty, challenge);

    // Nonce 값을 생성
    nonce = 12345;

    // Nonce 값을 서버로 전송
    if (write(sock, &nonce, sizeof(nonce)) == -1)
        errProc("write");

    close(sock);

    return 0;
}

void errProc(const char *str) {
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
    exit(1);
}

void errPrint(const char *str) {
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
}
