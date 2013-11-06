#include <cstdio>
#include <cstring>
#include "AES.h"
using namespace std;

AES::AES(char* input){
	unsigned char i, j, k, *tmp;
	if(input){
		setRoundKey(input);
	}
	for(i=0;i<4;++i){
		tmp = new unsigned char[4];
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
		state.push_back(tmp);
	}
}

AES::~AES(){
	clearAll(roundKey);
	clearAll(state);
}

void AES::keySchedule(){	//generate round key
	unsigned char *tmp, i, j, k;
	for(i=0,j=3;i<40;++i,++j){
		tmp = new unsigned char[4];
		if(!(i%4)){
			for(k=0;k<4;++k)
				tmp[k] = roundKey[j][(k+1)%4];
			//rotWord
			for(k=0;k<4;++k)
				tmp[k] = SBox[tmp[k]/16][tmp[k]%16] ^ Rcon[k][i/4] ^ roundKey[i][k];
			//subBytes & XOR
		}
		else{
			for(k=0;k<4;++k)
				tmp[k] = roundKey[i][k] ^ roundKey[j][k];
		}
		roundKey.push_back(tmp);
	}
}

void AES::setRoundKey(char* input){
	int i, j, k;
	unsigned char* tmp;
	if(roundKey.size())
		clearAll(roundKey);
	for(i=k=0;i<4;++i){
		tmp = new unsigned char[4];
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
		for(j=0;j<4&&input[k];++j)
			tmp[j] = (unsigned char)input[k++];
		roundKey.push_back(tmp);
	}
	keySchedule();
}

void AES::clearAll(vector<unsigned char*>& input){
	int i;
	for(i=input.size()-1;i>=0;--i){
		delete [] input[i];
		input.pop_back();
	}
}

void AES::addRoundKey(int round){
	unsigned char i, j, k=4*round;
	for(i=k;i<k+4;++i)
		for(j=0;j<4;++j)
			state[i%4][j] = state[i%4][j] ^ roundKey[i][j];
}

char* AES::encrypt(char* input){
	int i, j, k;
	for(i=k=0;i<4;++i)
		for(j=0;j<4;++j)
			state[i][j] = (unsigned char)input[k++];
	//initial round
	addRoundKey(0);
	//9 rounds
	for(i=1;i<10;++i){
		subBytes();
		shiftRows();
		mixColumns();
		addRoundKey(i);
	}
	//final round
	subBytes();
	shiftRows();
	addRoundKey(10);
	//convert to array
	for(i=k=0;i<4;++i)
		for(j=0;j<4;++j)
			text[k++] = state[i][j];
	text[k] = 0;
	return text;
}

char* AES::printable(char* input, int num){
	int i, j;
	for(i=j=0;i<num;++i)
			j += snprintf(text2+j, MAX_SIZE-j, "%02x", (unsigned char)input[i]);
	text2[j] = 0;
	return text2;
}

void AES::subBytes(){
	unsigned char tmp, i, j;
	for(i=0;i<4;++i)
		for(j=0;j<4;++j){
			tmp = state[i][j];
			state[i][j] = SBox[tmp/16][tmp%16];
		}
}

void AES::shiftRows(){
	unsigned char tmp[4][4], i, j;
	for(i=0;i<4;++i)
		for(j=0;j<4;++j)
			tmp[i][j] = state[(j+i)%4][i];
	for(i=0;i<4;++i)
		for(j=0;j<4;++j)
			state[j][i] = tmp[i][j];
}

void AES::mixColumns(){
	unsigned char i, j, h, a[4], b[4];
	for(i=0;i<4;++i){
		for(j=0;j<4;++j){
			a[j] = state[i][j];
			h = (unsigned char)((signed char)state[i][j] >> 7);
			b[j] = state[i][j] << 1;
			b[j] ^= 0x1B & h;
		}
		state[i][0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		state[i][1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		state[i][2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		state[i][3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
	}
}

char* AES::decrypt(char* input){
	int i, j, k;
	for(i=k=0;i<4;++i)
		for(j=0;j<4;++j)
			state[i][j] = input[k++];
	addRoundKey(10);
	invShiftRows();
	invSubBytes();
	for(i=9;i>0;--i){
		addRoundKey(i);
		invMixColumns();
		invShiftRows();
		invSubBytes();
	}
	addRoundKey(0);
	for(i=k=0;i<4;++i)
		for(j=0;j<4;++j)
			text[k++] = state[i][j];
	text[k] = 0;
	return text;
}

char* AES::processable(char* input){
	int i, j, len=strlen(input);
	char hxstr[len/2][3];
	for(i=j=0;i<len;i+=2,++j){
		hxstr[j][0] = input[i];
		hxstr[j][1] = input[i+1];
		hxstr[j][2] = 0;
	}
	for(i=0;i<len/2;++i)
		sscanf(hxstr[i], "%02x", (unsigned int*)&text2[i]);
	text2[i] = 0;
	return text2;
}

void AES::invSubBytes(){
	unsigned char tmp, i, j;
	for(i=0;i<4;++i)
		for(j=0;j<4;++j){
			tmp = state[i][j];
			state[i][j] = invSBox[tmp/16][tmp%16];
		}
}

void AES::invShiftRows(){
	unsigned char tmp[4][4], i, j;
	for(i=0;i<4;++i)
		for(j=0;j<4;++j)
			tmp[i][(j+i)%4] = state[j][i];
	for(i=0;i<4;++i)
		for(j=0;j<4;++j)
			state[j][i] = tmp[i][j];
}

void AES::invMixColumns(){
	unsigned char i, j, k, l, r[4], s[4], invMix[4]={0x0E, 0x0B, 0x0D, 0x09}, tmp[4][4];
	for(i=0;i<4;++i)
		for(j=0;j<4;++j)
			tmp[i][j] = state[i][j];
	for(i=0;i<4;++i)
		for(j=0;j<4;++j){
			for(k=0;k<4;++k){
				r[0] = tmp[i][k];
				for(l=1;l<4;++l){
					r[l] = r[l-1] << 1;
					if(r[l-1]&0x80)
						r[l] ^= 0x1B;
				}
				switch(invMix[(k-j+4)%4]){
					case 14:
						s[k] = r[1] ^ r[2] ^ r[3];
						break;
					case 13:
						s[k] = r[0] ^ r[2] ^ r[3];
						break;
					case 11:
						s[k] = r[0] ^ r[1] ^ r[3];
						break;
					case 9:
						s[k] = r[0] ^ r[3];
						break;
				}
			}
			state[i][j] = (unsigned char)(s[0] ^ s[1] ^ s[2] ^ s[3]);
		}
}
