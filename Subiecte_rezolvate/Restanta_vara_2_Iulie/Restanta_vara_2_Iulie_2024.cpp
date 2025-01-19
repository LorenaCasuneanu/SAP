#pragma warning(disable : 4996)
#include <iostream>
#include <fstream>
#include <string>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

using namespace std;

// Convert a string of hexadecimals into a byte array
static int hextext2bin(std::string hextext, unsigned char* bin)
{
	unsigned int i;
	unsigned int uchr;
	int res;

	for (i = 0; i < hextext.length(); i += 2) {
		res = sscanf(hextext.c_str() + i, "%2x", &uchr);
		if (!res) {
			/* return 0 immediately */
			return res;
		}
		bin[i / 2] = uchr;
	}
	return (i / 2);
}

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
void AES_decrypt(const unsigned char *inputKey, size_t keySize, unsigned char *ciphertext, size_t ciphertextLen, unsigned char* restoringtext) {
	AES_KEY aes_key;
	AES_set_decrypt_key(inputKey, keySize, &aes_key);

	for (unsigned int i = 0; i < ciphertextLen; i += AES_BLOCK_SIZE) {
		AES_decrypt(&ciphertext[i], &restoringtext[i], &aes_key);
	}
}

//scoate cheia RSA dintr-un array de bytes de forma PEM
void load_RSA_private_key(RSA** rsa, const unsigned char *key_data, size_t key_len) {
	BIO *bio = BIO_new_mem_buf(key_data, key_len);
	if (bio == nullptr) {
		cerr << "Error loading key data into BIO" << endl;
		return;
	}
	*rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
}

bool RSA_sign_message(unsigned char* input, size_t input_size, RSA *rsa_private, unsigned char* rsa_signature, size_t *sigLength) {

	unsigned char hash_input[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_size);
	SHA256_Final(hash_input, &ctx);

	*sigLength = RSA_private_encrypt(sizeof(hash_input), hash_input, rsa_signature, rsa_private, RSA_PKCS1_PADDING);
	return true;
}

int main()
{
	unsigned char *privateKey1_enc_with_AES, *privateKey2_enc_with_AES, *privateKey3_enc_with_AES;
	int len1, len2, len3;

	unsigned char AES_key[] = {
	  0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04,
	  0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12
	};

	if (!read_all_file("privateKey_1.enc", privateKey1_enc_with_AES, len1)) {
		cout << "Error loading privateKey_1.enc" << endl;
		return 1;
	}
	if (!read_all_file("privateKey_2.enc", privateKey2_enc_with_AES, len2)) {
		cout << "Error loading privateKey_2.enc" << endl;
		return 1;
	}
	if (!read_all_file("privateKey_3.enc", privateKey3_enc_with_AES, len3)) {
		cout << "Error loading privateKey_3.enc" << endl;
		return 1;
	}

	unsigned char pem_RSA_1[1000];
	unsigned char pem_RSA_2[1000];
	unsigned char pem_RSA_3[1000];
	AES_decrypt(AES_key, (sizeof(AES_key) * 8), privateKey1_enc_with_AES, len1, pem_RSA_1);
	AES_decrypt(AES_key, (sizeof(AES_key) * 8), privateKey2_enc_with_AES, len2, pem_RSA_2);
	AES_decrypt(AES_key, (sizeof(AES_key) * 8), privateKey3_enc_with_AES, len3, pem_RSA_3);

	RSA *privateKey1, *privateKey2, *privateKey3;
	load_RSA_private_key(&privateKey1, pem_RSA_1, len1);
	load_RSA_private_key(&privateKey2, pem_RSA_2, len2);
	load_RSA_private_key(&privateKey3, pem_RSA_3, len3);

	unsigned char *InBytes;
	int lengthIn;
	read_all_file(R"(C:\Users\nxf71449\source\repos\Restanta_vara_2_Iulie_2024\Restanta_vara_2_Iulie_2024\in.txt)", InBytes, lengthIn);

	unsigned char *signature1, *signature2, *signature3;
	size_t siglen1 = 0, siglen2 = 0, siglen3 = 0;
	signature1 = (unsigned char*)malloc(len1);
	signature2 = (unsigned char*)malloc(len2);
	signature3 = (unsigned char*)malloc(len3);

	RSA_sign_message(InBytes, lengthIn, privateKey1, signature1, &siglen1);
	RSA_sign_message(InBytes, lengthIn, privateKey2, signature2, &siglen2);
	RSA_sign_message(InBytes, lengthIn, privateKey3, signature3, &siglen3);

	unsigned char *eSignBytes;
	int lengthSig;
	read_all_file(R"(C:\Users\nxf71449\source\repos\Restanta_vara_2_Iulie_2024\Restanta_vara_2_Iulie_2024\eSign.sig)", eSignBytes, lengthSig);

	if (memcmp(eSignBytes, signature1, lengthSig) == 0) {
		printf("fis1");
	}
	if (memcmp(eSignBytes, signature2, lengthSig) == 0) {
		printf("fis2");
	}
	if (memcmp(eSignBytes, signature3, lengthSig) == 0) {
		printf("fis3");
	}

	RSA_free(privateKey1);
	RSA_free(privateKey2);
	RSA_free(privateKey3);

	free(signature1);
	free(signature2);
	free(signature3);
	delete[] InBytes;
}