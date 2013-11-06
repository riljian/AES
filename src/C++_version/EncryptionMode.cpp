#include "EncryptionMode.h"
#include <cstdio>
using namespace std;

void encryptMode::setIV(char* input){
	int i;
	for(i=0;i<16&&input[i];++i)
		IV[i] = input[i];
	for(;i<17;++i)
		IV[i] = 0;
}

void encryptMode::setKey(char* input){
	aes.setRoundKey(input);
	aes.setRoundKey(input);
}

void encryptMode::stringXOR(char* input1, char* input2){
	int i;
	for(i=0;i<16;++i)
		input1[i] = input1[i] ^ input2[i];
}

char* CBCmode::encrypt(char* input, int len){
	int blocks, i, j;
	memset(text3, 0, sizeof(text3));
	blocks = len%16 ? len/16+1 : len/16;
	for(i=j=0;i<blocks;++i){
		copynarray(text, input+16*i, 16);
		text[16] = 0;
		if(i)
			stringXOR(text, text2);
		else
			stringXOR(text, IV);
		copynarray(text2, aes.encrypt(text), 16);
		text2[16] = 0;
		copynarray(text3+i*16, text2, 16);
	}
	text3[i*16] = 0;
	return text3;
}

char* CBCmode::decrypt(char* input, int len){
	int i, j, blocks;
	char text4[17];
	memset(text3, 0, sizeof(text3));
	blocks = len%16 ? len/16+1 : len/16;
	for(i=j=0;i<blocks;++i){
		copynarray(text, input+16*i, 16);
		text[16] = 0;
		copynarray(text2, aes.decrypt(text), 16);
		text2[16] = 0;
		if(i)
			stringXOR(text2, text4);
		else
			stringXOR(text2, IV);
		copynarray(text3+i*16, text2, 16);
		copynarray(text4, text, 16);
		text4[16] = 0;
	}
	text3[i*16] = 0;
	return text3;
}

char* OFBmode::encrypt(char* input, int len){
	int blocks, i, j;
	memset(text3, 0, sizeof(text3));
	blocks = len%16 ? len/16+1 : len/16;
	for(i=j=0;i<blocks;++i){
		if(i)
			copynarray(text2, aes.encrypt(text2), 16);
		else
			copynarray(text2, aes.encrypt(IV), 16);
		text2[16] = 0;
		copynarray(text3+i*16, text2, 16);
	}
	for(i=0;i<len;++i)
		text3[i] = input[i] ^ text3[i];
	text3[len] = 0;
	return text3;
}

char* OFBmode::decrypt(char* input, int len){
	int blocks, i, j;
	memset(text3, 0, sizeof(text3));
	blocks = len%16 ? len/16+1 : len/16;
	for(i=j=0;i<blocks;++i){
		if(i)
			copynarray(text2, aes.encrypt(text2), 16);
		else
			copynarray(text2, aes.encrypt(IV), 16);
		text2[16] = 0;
		copynarray(text3+i*16, text2, 16);
	}
	for(i=0;i<len;++i)
		text3[i] = input[i] ^ text3[i];
	text3[len] = 0;
	return text3;
}

char* ECBmode::encrypt(char* input, int len){
	int blocks, i, j;
	memset(text3, 0, sizeof(text3));
	blocks = len%16 ? len/16+1 : len/16;
	for(i=j=0;i<blocks;++i){
		copynarray(text, input+16*i, 16);
		text[16] = 0;
		copynarray(text2, aes.encrypt(text), 16);
		text2[16] = 0;
		copynarray(text3+i*16, text2, 16);
	}
	text3[i*16] = 0;
	return text3;
}

char* ECBmode::decrypt(char* input, int len){
	int i, j, blocks;
	memset(text3, 0, sizeof(text3));
	blocks = len%16 ? len/16+1 : len/16;
	for(i=j=0;i<blocks;++i){
		copynarray(text, input+16*i, 16);
		text[16] = 0;
		copynarray(text2, aes.decrypt(text), 16);
		text2[16] = 0;
		copynarray(text3+i*16, text2, 16);
	}
	text3[i*16] = 0;
	return text3;
}

char* CTRmode::encrypt(char* input, int len){
	int blocks, i, j;
	char text4[17];
	memset(text3, 0, sizeof(text3));
	blocks = len%16 ? len/16+1 : len/16;
	copynarray(text4, IV, 16);
	text4[16] = 0;
	for(i=j=0;i<blocks;++i){
		copynarray(text, input+16*i, 16);
		text[16] = 0;
		copynarray(text2, aes.encrypt(text4), 16);
		text2[16] = 0;
		stringXOR(text2, text);
		copynarray(text3+i*16, text2, 16);
		counter(text4);
	}
	text3[i*16] = 0;
	return text3;
}

char* CTRmode::decrypt(char* input, int len){
	int i, j, blocks;
	char text4[17];
	memset(text3, 0, sizeof(text3));
	blocks = len%16 ? len/16+1 : len/16;
	copynarray(text4, IV, 16);
	text4[16] = 0;
	for(i=j=0;i<blocks;++i){
		copynarray(text, input+16*i, 16);
		text[16] = 0;
		copynarray(text2, aes.encrypt(text4), 16);
		text2[16] = 0;
		stringXOR(text2, text);
		copynarray(text3+i*16, text2, 16);
		counter(text4);
	}
	text3[i*16] = 0;
	return text3;
}

void CTRmode::counter(char* input){
}

char* CFBmode::encrypt(char* input, int len){
	int blocks, i, j, shiftbytes=1;
	memset(text3, 0, sizeof(text3));
	blocks = len%shiftbytes ? len/shiftbytes+1 : len/shiftbytes;
	copynarray(text, IV, 16);
	text[16] = 0;
	for(i=0;i<blocks;++i){
		if(i)
			copynarray(text2, aes.encrypt(text), 16);
		else
			copynarray(text2, aes.encrypt(text), 16);
		text2[16] = 0;
		for(j=0;j<shiftbytes;++j)
			text2[j] = text2[j] ^ input[i*shiftbytes+j];
		copynarray(text3+i*shiftbytes, text2, shiftbytes);
		shift(text, text2, shiftbytes);
	}
	text3[len] = 0;
	return text3;
}

char* CFBmode::decrypt(char* input, int len){
	int blocks, i, j, shiftbytes=1;
	memset(text3, 0, sizeof(text3));
	blocks = len%shiftbytes ? len/shiftbytes+1 : len/shiftbytes;
	copynarray(text, IV, 16);
	text[16] = 0;
	for(i=0;i<blocks;++i){
		if(i)
			copynarray(text2, aes.encrypt(text), 16);
		else
			copynarray(text2, aes.encrypt(text), 16);
		text2[16] = 0;
		for(j=0;j<shiftbytes;++j)
			text2[j] = text2[j] ^ input[i*shiftbytes+j];
		copynarray(text3+i*shiftbytes, text2, shiftbytes);
		shift(text, input+i*shiftbytes, shiftbytes);
	}
	text3[len] = 0;
	return text3;
}

void CFBmode::shift(char* input1, char* input2,  int bytes){
	int i, j;
	for(i=0;i<16-bytes;++i)
		input1[i] = input1[i+bytes];
	for(j=0;i<16;++i,++j)
		input1[i] = input2[j];
	input1[16] = 0;
}
