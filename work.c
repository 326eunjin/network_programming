#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>

#define BUFSIZE 256
#define MAX_PROCESSES 10

void errProc(const char *str) {
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
    exit(1);
}

void errPrint(const char *str) {
    fprintf(stderr, "%s: %s \n", str, strerror(errno));
}

void calculate_hash(const char *challenge, unsigned int nonce, unsigned char *hash)
{
    char data[256];
    snprintf(data, sizeof(data), "%s%u", challenge, nonce);

    SHA256((unsigned char *)data, strlen(data), hash);
}

int check_difficulty(unsigned char *hash, const int difficulty)
{
    int count = 0;
    for (int i = 0; i < difficulty / 2; i++)
    {
        if (hash[i] == 0)
        {
            count += 2;
        }
        else
        {
            break;
        }
    }

    if (difficulty % 2 == 1 && (hash[difficulty / 2] & 0xF0) == 0)
    {
        count++;
    }

    return count >= difficulty;
}

void find_nonce(const int write_fd, const char *challenge, const int difficulty, const unsigned int start_nonce, const unsigned int end_nonce)
{
    unsigned int nonce = start_nonce;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    while (nonce <= end_nonce)
    {
        calculate_hash(challenge, nonce, hash);

        if (check_difficulty(hash, difficulty))
        {
            printf("찾은 nonce 값: %u\n", nonce); // nonce 값을 출력
            write(write_fd, &nonce, sizeof(unsigned int)); // Write the nonce to the pipe
            close(write_fd);
            return;
        }

        nonce++;
    }

    close(write_fd);
}

int main(int argc, char **argv)
{
    int clntSd;
    struct sockaddr_in srvAddr;
    char rBuff[BUFSIZ];
    int difficulty;
    char challenge[BUFSIZ];
    unsigned int nonce;

    unsigned int num_nonce_per_process = (UINT32_MAX + 1) / MAX_PROCESSES;
    pid_t pids[MAX_PROCESSES];
    int pipes[MAX_PROCESSES][2];

    if (argc != 3)
    {
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
    
    for (unsigned int i = 0; i < MAX_PROCESSES; i++)
    {
        if (pipe(pipes[i]) == -1)
        {
            fprintf(stderr, "Failed to create pipe.\n");
            return 1;
        }

        unsigned int start_nonce = i * num_nonce_per_process;
        unsigned int end_nonce = (i + 1) * num_nonce_per_process - 1;

        if (i == MAX_PROCESSES - 1)
        {
            end_nonce = UINT32_MAX;
        }

        pid_t pid = fork();

        if (pid < 0)
        {
            fprintf(stderr, "Fork failed.\n");
            return 1;
        }
        else if (pid == 0)
        {
            close(pipes[i][0]); // Close the read end of the pipe in the child process
            find_nonce(pipes[i][1], challenge, difficulty, start_nonce, end_nonce);
            exit(0);
        }
        else
        {
            close(pipes[i][1]); // Close the write end of the pipe in the parent process
            pids[i] = pid;
        }
    }

    for (unsigned int i = 0; i < MAX_PROCESSES; i++)
    {
        if (read(pipes[i][0], &nonce, sizeof(unsigned int)) != -1)
        {
            break;
        }
    }
    for (unsigned int i = 0; i < MAX_PROCESSES; i++)
    {
        close(pipes[i][0]); // Close the read end of the pipe in the parent process
    }

    // 서버로 nonce 값 전송
    if (write(clntSd, &nonce, sizeof(nonce)) == -1)
    {
        perror("write");
        exit(1);
    }

    close(clntSd);

    return 0;
}
