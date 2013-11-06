#include <cstdio>
#include <cstring>
#include "EncryptionMode.h"
using namespace std;

int main(int argc, char* argv[]){
	encryptMode *EM;
	char str[MAX_SIZE];
	int len;

	if(!strcmp("CBC", argv[1]))
		EM = new CBCmode;
	else if(!strcmp("ECB", argv[1]))
		EM = new ECBmode;
	else if(!strcmp("CFB", argv[1]))
		EM = new CFBmode;
	else if(!strcmp("OFB", argv[1]))
		EM = new OFBmode;
	else if(!strcmp("CTR", argv[1]))
		EM = new CTRmode;

	printf("\nInput initialization vector:\n");
	fgets(str, MAX_SIZE, stdin);
	str[strlen(str)-1] = 0;
	EM->setIV(str);

	printf("\nInput key:\n");
	fgets(str, MAX_SIZE, stdin);
	str[strlen(str)-1] = 0;
	EM->setKey(str);

	printf("\nInput plain text:\n");
	fgets(str, MAX_SIZE, stdin);
	str[strlen(str)-1] = 0;
	len = strlen(str);

	printf("\nCipher text:\n");
	if(!strcmp(argv[1], "CFB")||!strcmp(argv[1], "OFB"))
		printf("%s\n", EM->aes.printable(EM->encrypt(str, len), len));
	else
		printf("%s\n", EM->aes.printable(EM->encrypt(str, len), 16*(len%16?len/16+1:len/16)));

	printf("\nInput cipher text:\n");
	fgets(str, MAX_SIZE, stdin);
	str[strlen(str)-1] = 0;
	len = strlen(str)/2;

	printf("\nPlain text:\n");
	printf("%s\n", EM->decrypt(EM->aes.processable(str), len));

	return 0;
}
