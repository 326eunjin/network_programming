#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>

void errProc(const char *str);
void errPrint(const char *str);

void calculateNonce(int sock, unsigned int difficulty, const char *challenge, unsigned int start, unsigned int end, int *result_pipe)
{
    unsigned int nonce;
    char hash[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256_CTX sha256;

    for (nonce = start; nonce <= end; nonce++)
    {
        // Calculate hash
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, &nonce, sizeof(nonce));
        SHA256_Update(&sha256, challenge, strlen(challenge));
        SHA256_Final((unsigned char *)hash, &sha256);

        // Convert hash to hex string
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            sprintf(hex + (i * 2), "%02x", (unsigned char)hash[i]);
        hex[SHA256_DIGEST_LENGTH * 2] = '\0';

        // Check difficulty
        int leadingZeros = 0;
        for (int i = 0; i < SHA256_DIGEST_LENGTH * 2; i++)
        {
            if (hex[i] == '0')
                leadingZeros++;
            else
                break;
        }

        if (leadingZeros >= difficulty)
        {
            printf("Nonce found: %u\n", nonce);
            printf("Hash: %s\n", hex);

            // Nonce 값을 부모 프로세스로 전송
            if (write(result_pipe[1], &nonce, sizeof(nonce)) == -1)
                errProc("write");

            close(sock);
            exit(0);
        }
    }

    close(sock);

    // 프로세스 자체 종료
    kill(getpid(), SIGTERM);
}

int main(int argc, char **argv)
{
    int sock;
    struct sockaddr_in servAddr;
    int strLen;
    int difficulty;
    char challenge[BUFSIZ];
    unsigned int rangeSize;
    unsigned int start, end;
    pid_t childPids[4]; // 자식 프로세스의 PID 저장 배열
    int result_pipe[2]; // 자식 프로세스에서 부모 프로세스로 결과를 전달하기 위한 파이프

    if (argc != 3)
    {
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

    // 계산 범위 설정
    rangeSize = UINT_MAX / 2 / 4;
    start = UINT_MAX / 2 + 1;

    // 파이프 생성
    if (pipe(result_pipe) == -1)
        errProc("pipe");

    // Fork 멀티프로세스 생성
    for (int i = 0; i < 4; i++)
    {
        end = start + rangeSize;
        pid_t pid = fork();

        if (pid < 0)
        {
            errProc("fork");
        }
        else if (pid == 0)
        {
            // 자식 프로세스는 calculateNonce 함수 호출
            close(result_pipe[0]); // 자식 프로세스에서 읽는 파이프 닫음
            calculateNonce(sock, difficulty, challenge, start, end, result_pipe);
        }
        else
        {
            childPids[i] = pid; // 자식 프로세스의 PID 저장
        }

        start = end + 1;
    }

    close(result_pipe[1]); // 부모 프로세스에서 쓰는 파이프 닫음

    unsigned int fastest_nonce;
    int fastest_found = 0;
    for (int i = 0; i < 4; i++)
    {
        unsigned int nonce;
        ssize_t bytes_read = read(result_pipe[0], &nonce, sizeof(nonce));
        if (bytes_read == sizeof(nonce))
        {
            if (!fastest_found || nonce < fastest_nonce)
            {
                fastest_nonce = nonce;
                fastest_found = 1;
            }
        }
    }

    if (fastest_found)
    {
        printf("가장 빠른 Nonce: %u\n", fastest_nonce);
        // 가장 빠른 nonce 값을 서버로 전송
        if (write(sock, &fastest_nonce, sizeof(fastest_nonce)) == -1)
            errProc("write");
    }
    else
    {
        printf("결과를 찾지 못했습니다.\n");
    }

    // 모든 자식 프로세스의 종료를 기다림
    for (int i = 0; i < 4; i++)
    {
        waitpid(childPids[i], NULL, 0);
    }

    close(sock);

    return 0;
}

void errProc(const char *str)
{
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
    exit(1);
}

void errPrint(const char *str)
{
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
}
