#pragma warning(disable : 4996)
#include <iostream>
#include <fstream>
#include <string>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

using namespace std;

//load_file citeste tot ce e intr-un fisier
bool read_all_file(const char* filename, unsigned char* &buffer, int &length) {

	ifstream file(filename, ios::binary | ios::ate);
	if (!file.is_open()) {
		cerr << "Error opening file: " << filename << endl;
		return false;
	}
	file.seekg(0, file.end);
	length = file.tellg();
	file.seekg(0, file.beg);
	buffer = new unsigned char[length];
	file.read(reinterpret_cast<char*>(buffer), length);
	file.close();
	return true;
}

void AES_CBC_decrypt(const unsigned char *inputKey, size_t keySize, unsigned char *IV, unsigned char *ciphertext, size_t ciphertextLen, unsigned char* restoringtext) {
	
	AES_KEY aes_key;
	AES_set_decrypt_key(inputKey, keySize, &aes_key);

	AES_cbc_encrypt(ciphertext, restoringtext, ciphertextLen, &aes_key, IV, AES_DECRYPT);
}

int main()
{
	//Subiectul 1
	unsigned char AES_key[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x07, 0x06, 0x05, 0x00, 0x00, 0x00, 0x00 };

	unsigned char IV[] = {
		 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04,
		 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12 };

	unsigned char *fileContent;
	int fileContentLen;
		
	if (!read_all_file("encrypted.aes", fileContent, fileContentLen)) {
		cout << "Error loading encrypted.aes" << endl;
		return 1;
	}

	unsigned char* restoringtext;
	restoringtext = (unsigned char*)malloc(fileContentLen);
	AES_CBC_decrypt(AES_key,  (sizeof(AES_key) * 8), IV, fileContent, fileContentLen, restoringtext);

	printf("%s", restoringtext);
	printf("\n");

	//Subiectul 2
	unsigned char *esignfileContent;
	int esignfileContentLen;

	if (!read_all_file("esign.sig", esignfileContent, esignfileContentLen)) {
		cout << "Error loading esign.sig" << endl;
		return 1;
	}

	FILE* fpublic = fopen("public.pem", "r");
	RSA* rsa_public;
	rsa_public = PEM_read_RSAPublicKey(fpublic, NULL, NULL, NULL);
	int rsa_size = RSA_size(rsa_public); 

	unsigned char RSA_decrypt_output[SHA256_DIGEST_LENGTH];
	RSA_public_decrypt(esignfileContentLen, esignfileContent, RSA_decrypt_output, rsa_public, RSA_PKCS1_PADDING);

	//Subiectul 3
	unsigned char hash_fileContent[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, restoringtext, fileContentLen);
	SHA256_Final(hash_fileContent, &ctx);

	if (memcmp(RSA_decrypt_output, hash_fileContent, SHA256_DIGEST_LENGTH) == 0) {
		printf("Valid signature");
	}
	else {
		printf("Invalid signature");
	}

}

