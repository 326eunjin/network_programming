// working server

#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>

void cal_sha256(const unsigned char *data, size_t data_len, unsigned char *hash) { // 문자열 -> 해쉬값 바꾸는 함수
	SHA256_CTX sha256_ctx; // sha256 구조체
	SHA256_Init(&sha256_ctx); // 구조체 초기화
	SHA256_Update(&sha256_ctx, data, data_len);
	SHA256_Final(hash, &sha256_ctx); // hash에 해쉬값 저장
}
int main() {

	// main에서 난이도와 challenge 값 받기
	// main으로 결과값 전송하기
	// 멀티프로세스/멀티스레드 사용하기
	// 다른 working서버가 nonce 먼저 찾으면 종료
	
	const char *message = "Hello World"; // chaellenge(학번or이름)
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int nonce = 0;

	while(1){
		char input[256]; // challenge||nonce 값을 저장
		snprintf(input, sizeof(input), "%s%d", message, nonce);

		cal_sha256((const unsigned char *)input, strlen(input), hash);

		if (hash[0] == 0 && hash[1] == 0 && hash[2] == 0 && hash[3] == 0){
			printf("Nonce found: %d\n", nonce); // nonce 값 출력
			printf("SHA256 hash: "); // 해쉬값 출력
			for (int i=0;i<SHA256_DIGEST_LENGTH;i++){
				printf("%02x", hash[i]);
			}
			printf("\n");
			break;
		}
		nonce++; // nonce 값 1씩 증가해가며 탐색
	}
	return 0;
}
