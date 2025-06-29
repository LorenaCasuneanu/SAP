#pragma warning(disable : 4996)
#include <iostream>
#include <fstream>
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
void compute_hash(const char* input, size_t input_len, unsigned char* outputHash)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(outputHash, &ctx);
}
int main()
{
	//Exer 1
	unsigned char aes_key_bytes[16] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x00, 0x00, 0x00, 0x00 };
	unsigned char iv[16] = { 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12 };

	AES_KEY aes_key;
	AES_set_decrypt_key(aes_key_bytes, sizeof(aes_key_bytes) * 8, &aes_key);

	unsigned char* buffer_encrypted = nullptr;
	int buffer_encrypted_len = 0;

	if (!read_all_file("encrypted.aes", buffer_encrypted, buffer_encrypted_len)) {
		cout << "Error reading encrypted.aes " << endl;
		return 1;
	}

	unsigned char* restoringtext = nullptr;
	unsigned char partial_block = buffer_encrypted_len % AES_BLOCK_SIZE ? 1 : 0;
	unsigned char ciphertext_blocks = buffer_encrypted_len / AES_BLOCK_SIZE + partial_block;
	restoringtext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

	AES_cbc_encrypt(buffer_encrypted, restoringtext, buffer_encrypted_len, &aes_key, iv, AES_DECRYPT);

	for (int i = 0; i < buffer_encrypted_len; i++) {
		cout << restoringtext[i];
	}
	cout << "\n";

	//Exer 2
	unsigned char buffer_message_hash[SHA256_DIGEST_LENGTH];
	unsigned char myOutputHash[SHA256_DIGEST_LENGTH];
	unsigned char* buffer_signature = nullptr;
	int buffer_singature_len = 0;

	if (!read_all_file("esign.sig", buffer_signature, buffer_singature_len)) {
		cout << "Error reading esign.sig" << endl;
		return 1;
	}

	RSA* rsa_public;
	FILE* fpublic = fopen("public.pem", "r");
	rsa_public = PEM_read_RSAPublicKey(fpublic, NULL, NULL, NULL);

	RSA_public_decrypt(buffer_singature_len, buffer_signature, buffer_message_hash, rsa_public, RSA_PKCS1_PADDING);
	compute_hash((const char *)restoringtext, buffer_encrypted_len, myOutputHash);

	int result = memcmp(buffer_message_hash, myOutputHash, SHA256_DIGEST_LENGTH);

	if (result)
	{
		printf("Wrong signature!\n");
	}
	else
	{
		printf("Signature has been verified!\n");
	}

}

