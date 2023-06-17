#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>

#define BUFSIZE 256
#define MAX_PROCESSES 4

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

    unsigned int nonce;
    int clntSd;
    int count = 0;
    struct sockaddr_in clnt_addr;
    char challenge[BUFSIZE]; // 챌린지값 저장
    int difficulty;

    unsigned int num_nonce_per_process = (UINT32_MAX + 1) / 8;
    pid_t pids[8];
    int pipes[8][2];

    clntSd = socket(AF_INET, SOCK_STREAM, 0); // 클라이언트 소켓
    if (clntSd == -1)
    {
        perror("socket");
        exit(1);
    }

    // 서버와 tcp connection
    memset(&clnt_addr, 0, sizeof(clnt_addr));
    clnt_addr.sin_family = AF_INET;
    clnt_addr.sin_addr.s_addr = inet_addr(argv[1]);
    clnt_addr.sin_port = htons(atoi(argv[2]));

    if (connect(clntSd, (struct sockaddr *)&clnt_addr, sizeof(clnt_addr)) == -1)
    {
        perror("connect");
        close(clntSd);
        exit(1);
    }
    printf("통신완료\n");
    // 서버에서 전송한 challenge와 난이도 받기
    while (1)
    {
        // Challenge and difficulty reading
        memset(challenge, 0, sizeof(challenge));
        if (read(clntSd, challenge, sizeof(challenge)) == -1)
        {
            perror("read");
            exit(1);
        }
        count++;
        printf("challenge: %s\n", challenge);

        memset(&difficulty, 0, sizeof(int));
        if (read(clntSd, &difficulty, sizeof(int)) == -1)
        {
            perror("read");
            exit(1);
        }
        printf("difficulty: %d\n", difficulty);

        // nonce 값 계산
        for (unsigned int i = 0; i < 8; i++)
        {
            if (pipe(pipes[i]) == -1)
            {
                fprintf(stderr, "Failed to create pipe.\n");
                return 1;
            }

            unsigned int start_nonce = i * num_nonce_per_process;
            unsigned int end_nonce = (i + 1) * num_nonce_per_process - 1;

            if (i == 8 - 1)
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

        for (unsigned int i = 0; i < 8; i++)
        {
            if (read(pipes[i][0], &nonce, sizeof(unsigned int)) != -1)
            {
                break;
            }
        }

        for (unsigned int i = 0; i < 8; i++)
        {
            close(pipes[i][0]); // Close the read end of the pipe in the parent process
        }

        // 서버로 nonce 값 전송
        if (write(clntSd, nonce, sizeof(nonce)) == -1)
        {
            perror("write");
            exit(1);
        }
    }
    close(clntSd);

    return 0;
}
