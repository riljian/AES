main: main.o EncryptionMode.o AES.o
	g++ -o main main.o AES.o EncryptionMode.o
	rm main.o AES.o EncryptionMode.o
main.o: main.cpp AES.h EncryptionMode.h
	g++ -c main.cpp
EncryptionMode.o: EncryptionMode.h EncryptionMode.cpp AES.h
	g++ -c EncryptionMode.cpp
AES.o: AES.cpp AES.h
	g++ -c AES.cpp
