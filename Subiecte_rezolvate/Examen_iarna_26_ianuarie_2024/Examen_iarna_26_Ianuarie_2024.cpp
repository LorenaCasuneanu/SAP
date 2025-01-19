#pragma warning(disable : 4996)
#include <iostream>
#include <fstream>
#include <string>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

using namespace std;

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

void calculate_hash(unsigned char* input, size_t input_size, unsigned char* outputHash) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_size);
	SHA256_Final(outputHash, &ctx);
}

void AES_CBC_encrypt(const unsigned char *inputKey, size_t keySize, unsigned char *IV, unsigned char *plaintext, size_t plaintextLen, unsigned char* ciphertext) {

	AES_KEY aes_key;
	AES_set_encrypt_key(inputKey, keySize, &aes_key);

	AES_cbc_encrypt(plaintext, ciphertext, plaintextLen, &aes_key, IV, AES_ENCRYPT);
}

bool RSA_sign_message(unsigned char* input, size_t input_size, RSA *rsa_private, unsigned char* rsa_signature, size_t *sigLength) {

	unsigned char hash_input[SHA256_DIGEST_LENGTH];
	calculate_hash(input, input_size, hash_input);

	*sigLength = RSA_private_encrypt(sizeof(hash_input), hash_input, rsa_signature, rsa_private, RSA_PKCS1_PADDING);
	return true;
}

int main()
{
	unsigned char IV[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x07, 0x06, 0x05, 0x00, 0x00, 0xFF, 0xFF };   //DACA VREAU DECRYPT --> SA FAC COPIE LA IV CA SE MODIFICA

	unsigned char *namefileContent;
	int namefileContentLen;

	if (!read_all_file("name.txt", namefileContent, namefileContentLen)) {
		cout << "Error loading name.txt" << endl;
		return 1;
	}

	unsigned char nameHash[SHA256_DIGEST_LENGTH];
	calculate_hash(namefileContent, namefileContentLen, nameHash);

	printf("Hash for name is: ");
	for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02X", nameHash[i]);

	unsigned char *keyfileContent;
	int keyfileContentLen;

	if (!read_all_file("aes.key", keyfileContent, keyfileContentLen)) {
		cout << "Error loading aes.key" << endl;
		return 1;
	}

	unsigned char* encryptedName;
	encryptedName = (unsigned char*)malloc(namefileContentLen);
	AES_CBC_encrypt(keyfileContent, keyfileContentLen * 8, IV, namefileContent, namefileContentLen, encryptedName);

	FILE* f = fopen("enc_name.aes", "wb+");
	fwrite(encryptedName, namefileContentLen, 1, f);
	fclose(f);

	//Subiectul 3
	RSA *rsa_kp;
	RSA *rsa_private, *rsa_public;
	rsa_kp = RSA_generate_key(1024, 65535, NULL, NULL);

	int a = RSA_check_key(rsa_kp); // validate the just created RSA key pair

	FILE* fprivate = fopen("RSAPrivateKey.pem", "wb");
	PEM_write_RSAPrivateKey(fprivate, rsa_kp, NULL, NULL, 0, NULL, NULL); // save the private key components in PEM format file
	fclose(fprivate);
	FILE* fpublic = fopen("RSAPublicKey.pem", "wb");
	PEM_write_RSAPublicKey(fpublic, rsa_kp); // save the public key components in PEM format file
	fclose(fpublic);

	RSA_free(rsa_kp);

	FILE* fprivateRead = fopen("RSAPrivateKey.pem", "r");
	rsa_private = PEM_read_RSAPrivateKey(fprivateRead, NULL, NULL, NULL);
	fclose(fprivateRead);

	int rsa_size = RSA_size(rsa_private); 
	unsigned char* rsa_signature = (unsigned char*)malloc(rsa_size);
	size_t siglen = 0;
	RSA_sign_message(encryptedName, namefileContentLen, rsa_private, rsa_signature, &siglen);
	RSA_free(rsa_private);

	FILE* g = fopen("sign.sig", "wb+");
	fwrite(rsa_signature, siglen, 1, f);
	fclose(g);

	unsigned char hash_validated[SHA256_DIGEST_LENGTH];
	calculate_hash(encryptedName, namefileContentLen, hash_validated);

	FILE* fpublicRead = fopen("RSAPublicKey.pem", "r");
	rsa_public = PEM_read_RSAPublicKey(fpublicRead, NULL, NULL, NULL);
	fclose(fpublicRead);

	//verificare semnatura

	unsigned char output[SHA256_DIGEST_LENGTH];
	RSA_public_decrypt(siglen, rsa_signature, output, rsa_public, RSA_PKCS1_PADDING);

	int result = memcmp(output, hash_validated, sizeof(SHA256_DIGEST_LENGTH));
	if (result) {
		printf("Wrong signature!\n");
	}
	else {
		printf("Signature has been verified!\n");
	}


}


