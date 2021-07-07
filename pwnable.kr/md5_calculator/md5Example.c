#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

#pragma comment(lib, "libeay32.lib")

int main(int argc, char *argv[]) {
	unsigned char data[MD5_DIGEST_LENGTH + 1];
	char buf[4096];
	int len;
	memset(data, 0, MD5_DIGEST_LENGTH + 1);
	while(1) {
		printf("Input data : ");
		fflush(stdin);
		scanf("%s", buf);
		len = strlen(buf);
		MD5((unsigned char*) buf, len, data);
		printf("data is : %s\n", buf);
		printf("md5 is : ");
		for(int i = 0; i < 16; i++) printf("%02x", data[i]);
		printf("\n");
	}
}
