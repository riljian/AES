#ifndef encryptionmode_h
#define encryptionmode_h

#include <vector>
#include <cstring>
#include "AES.h"
using namespace std;

class encryptMode{
	public:
		void setIV(char*);
		void setKey(char*);
		virtual char* encrypt(char*, int)=0;
		virtual char* decrypt(char*, int)=0;
		virtual ~encryptMode(){};
		AES aes;
	protected:
		void stringXOR(char*, char*);
		char IV[17], text[17], text2[17], text3[MAX_SIZE];
};

class CBCmode:public encryptMode{
	public:
		char* encrypt(char*, int);
		char* decrypt(char*, int);
		~CBCmode(){};
};

class OFBmode:public encryptMode{
	public:
		char* encrypt(char*, int);
		char* decrypt(char*, int);
		~OFBmode(){};
};

class ECBmode:public encryptMode{
	public:
		char* encrypt(char*, int);
		char* decrypt(char*, int);
		~ECBmode(){};
};

class CTRmode:public encryptMode{
	public:
		char* encrypt(char*, int);
		char* decrypt(char*, int);
		~CTRmode(){};
	private:
		void counter(char*);
};

class CFBmode:public encryptMode{
	public:
		char* encrypt(char*, int);
		char* decrypt(char*, int);
		~CFBmode(){};
	private:
		void shift(char*, char*, int);
};

#endif
