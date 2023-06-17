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

/*
void calculate_hash(const char *input, const unsigned int nonce, unsigned char *hash) {
	char data[256];
	snprintf(data, sizeof(data), "%s%u", input, nonce);
	SHA256((unsigned char *)data, strlen(data), hash);
}
int check_difficulty(unsigned char *hash, const int difficulty){
	int count=0;
	for (int i=0;i<difficulty/2;i++) {
		if (hash[i]==0) count += 2;
		else break;
	}
	if (difficulty%2 == 1 && (hash[difficulty/2] & 0xF0) == 0) 
		count++;
}
void find_nonce(const char *input, const int difficulty, counst unsigned int start_nonce, unsigned int end_nonce) {
	unsigned int nonce = start_nonce;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	while (nonce <= end_nonce) {
		calculate_hash(input, nonce, hash);
		
		if (check_difficulty(hash, difficulty)) {
			printf("Hash: ");
			for (int i=0;i<SHA256_DIGEST_LENGTH;i++) {
				printf("%02x", hash[i]);
			}
		printf("\nNonce: %u\n", nonce);
		exit(0);
		}
	nonce++;
	}
}
*/

int main(int argc, char **argv){
	
	unsigned int nonce;
	int clntSd;
	int count = 0;
	struct sockaddr_in clnt_addr;
	char challenge[BUFSIZE]; // 챌린지값 저장
	char difficulty[BUFSIZE]; // 난이도 저장 (문자열 아님 정수?)
	// int difficulty;

	clntSd = socket(AF_INET, SOCK_STREAM, 0); // 클라이언트 소켓
	if (clntSd == -1) {
		perror("socket");
		exit(1);
	}

	// 서버와 tcp connection
	memset(&clnt_addr, 0, sizeof(clnt_addr));
	clnt_addr.sin_family = AF_INET;
	clnt_addr.sin_addr.s_addr = inet_addr(argv[1]);
	clnt_addr.sin_port = htons(atoi(argv[2]));

	if (connect(clntSd, (struct sockaddr *) &clnt_addr, sizeof(clnt_addr)) == -1){
		perror("connect");
		close(clntSd);
		exit(1);
	}

	// 서버에서 전송한 challenge와 난이도 받기
	while (1) {
		if (count == 0) { // 챌린지 먼저 받음
		memset(challenge, 0 , sizeof(challenge));
		if (read(clntSd, challenge, sizeof(challenge)) == -1) {
			perror("read");
			exit(1);
		}
		count++;
		printf("challenge: %s", challenge);
		}
		if (count == 1) { // 난이도 
		memset(difficulty, 0, sizeof(difficulty));
		if (read(clntSd, difficulty, sizeof(difficulty)) == -1) {
			perror("read");
			exit(1);
		}
		printf("diffuculty: %s", difficulty);
		}
	}

	// nonce 값 계산
		
	// 서버로 nonce 값 전송
	if (write(clntSd, nonce, sizeof(nonce)) == -1) {
		perror("write");
		exit(1);
	}
	
	close(clntSd);

	return 0;
}
