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

void calculate_hash(const char* input, unsigned int nonce, unsigned char* hash) {
    char data[256];
    snprintf(data, sizeof(data), "%s%u", input, nonce);

    SHA256((unsigned char*)data, strlen(data), hash);
}

int check_difficulty(unsigned char* hash, const int difficulty) {
    int count = 0;
    for (int i = 0; i < difficulty / 2; i++) {
        if (hash[i] == 0) {
            count += 2; 
        }
        else {
            break;
        }
    }

    if (difficulty % 2 == 1 && (hash[difficulty / 2] & 0xF0) == 0) {
        count++;
    }

    return count >= difficulty;
}

void find_Nonce(int sock, unsigned int difficulty, const char *challenge, unsigned int start, unsigned int end)
{
    unsigned int nonce;
    char hash[SHA256_DIGEST_LENGTH];

    for (nonce = start; nonce <= end; nonce++) { // start부터 end까지 nonce 탐색
    
        // Calculate hash
        calculate_hash(challenge, nonce, hash); // 'challenge||nonce'의 해시값 계산

        if (check_difficulty(hash, difficulty)) { // 해시값이 난이도 만족하는지 검사
            write(sock, &nonce, sizeof(nonce)); // 만족하면 nonce 서버로 전송하기
            close(sock);
            exit(0);
        }
    }
    printf("not found\n");
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
    pid_t pid;
    unsigned int rangeSize;
    unsigned int start, end;

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

    // 챌린지 값을 서버로부터 수신
    if (read(sock, challenge, BUFSIZ) == -1)
        errProc("read");

    printf("난이도: %d, 도전 값: %s\n", difficulty, challenge);

    // 계산 범위 설정
    rangeSize = UINT_MAX/2 / 4;
    start = 0;

    // Fork 멀티프로세스 생성
    for (int i = 0; i < 4; i++) { // 범위를 4개로 나눠서 계산
        end = start + rangeSize;
        pid = fork();

        if (pid < 0) {
            errProc("fork");
        }
        else if (pid == 0) { // 자식 프로세스는 calculateNonce 함수 호출
            find_Nonce(sock, difficulty, challenge, start, end);
        }
        start = end + 1; 
    }

    // 부모 프로세스는 자식 프로세스의 종료를 기다림
    for (int i = 0; i < 4; i++)
    {
        wait(NULL);
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
