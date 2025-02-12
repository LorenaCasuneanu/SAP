#include <malloc.h>
#include "xor.h"

// Win
//		1. compile the library source code stored by ex12.c and defined by xor.h (get the file lib.o)
//				gcc -c ./ex12.c -o ./lib.o
//		2. create the dynamic library file (shared object)
//				gcc -shared ./lib.o -o ./sharedlib.so

//could be much more complicated
unsigned char* encryptXor(unsigned char* buf, unsigned char* key) {
    unsigned int i = 0;
    unsigned char* encBuf = (unsigned char*) malloc( BUF_SIZE * sizeof(unsigned char));
    
        for (i = 0; i < BUF_SIZE; i++) {
            encBuf[i] = buf[i] ^ key[i];
        }

    return encBuf;
}

//could be much more complicated
unsigned char* decryptXor(unsigned char* buf, unsigned char* key) {
    unsigned int i = 0;
    unsigned char* decBuf = (unsigned char*) malloc( BUF_SIZE *sizeof(unsigned char));

        for (i = 0; i < BUF_SIZE; i++) {
            decBuf[i] = buf[i] ^ key[i];
        }

    return decBuf;
}

// just XOR function
unsigned char* xorArray(unsigned char* buf1, unsigned char* buf2, unsigned int bSize) {
    unsigned int i = 0;
    unsigned char* rBuf = (unsigned char*) malloc( bSize * sizeof(unsigned char));
    
        for (i = 0; i < bSize; i++) {
            rBuf[i] = buf1[i] ^ buf2[i];
        }

    return rBuf;
}