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
void AES_decrypt_data(unsigned char* key_bytes, unsigned char* input, size_t input_len, unsigned char*& output_decrypted)
{
	AES_KEY aes_key;
	AES_set_decrypt_key(key_bytes, 128, &aes_key);

	unsigned char partial_block = input_len % AES_BLOCK_SIZE ? 1 : 0;
	unsigned char ciphertext_blocks = input_len / AES_BLOCK_SIZE + partial_block;
	output_decrypted = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

	for (unsigned int i = 0; i < ciphertext_blocks * AES_BLOCK_SIZE; i += AES_BLOCK_SIZE)
	{
		AES_decrypt(input + i, output_decrypted + i, &aes_key);
	}
}

void load_RSA_private_key(unsigned char* rsa_pem_bytes, size_t rsa_pem_len, RSA*& rsa) {

	ofstream pem("privKeySender.pem");
	FILE *f;

	for (int i = 0; i <= rsa_pem_len; i++) {
		pem << rsa_pem_bytes[i];
	}
	pem.close();

	f = fopen("privKeySender.pem", "r");
	rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	fclose(f);
}

void RSA_signature(unsigned char* input, size_t input_len, RSA* rsa_key, unsigned char* outputSigned) {

	unsigned char outputHash[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(outputHash, &ctx);

	RSA_private_encrypt(SHA256_DIGEST_LENGTH, outputHash, outputSigned, rsa_key, RSA_PKCS1_PADDING); // encryption for e-signature made by using the PRIVATE key
}

int main()
{
	unsigned char aes_key_bytes[16] = { 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04,
										0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12 };

	unsigned char* buffer_enc_private_key_1 = nullptr;
	unsigned char* buffer_dec_private_key_1 = nullptr;
	int length_enc_private_key_1 = 0;

	unsigned char* buffer_enc_private_key_2 = nullptr;
	unsigned char* buffer_dec_private_key_2 = nullptr;
	int length_enc_private_key_2 = 0;

	unsigned char* buffer_enc_private_key_3 = nullptr;
	unsigned char* buffer_dec_private_key_3 = nullptr;
	int length_enc_private_key_3 = 0;

	if (!read_all_file("privateKey_1.enc", buffer_enc_private_key_1, length_enc_private_key_1)) {
		cout << "Error loading privateKey_1.enc" << endl;
		return 1;
	}
	if (!read_all_file("privateKey_2.enc", buffer_enc_private_key_2, length_enc_private_key_2)) {
		cout << "Error loading privateKey_2.enc" << endl;
		return 1;
	}
	if (!read_all_file("privateKey_3.enc", buffer_enc_private_key_3, length_enc_private_key_3)) {
		cout << "Error loading privateKey_3.enc" << endl;
		return 1;
	}

	AES_decrypt_data(aes_key_bytes, buffer_enc_private_key_1, length_enc_private_key_1, buffer_dec_private_key_1);
	AES_decrypt_data(aes_key_bytes, buffer_enc_private_key_2, length_enc_private_key_2, buffer_dec_private_key_2);
	AES_decrypt_data(aes_key_bytes, buffer_enc_private_key_3, length_enc_private_key_3, buffer_dec_private_key_3);

	RSA *privateKey1 = nullptr;
	RSA *privateKey2 = nullptr;
	RSA *privateKey3 = nullptr;

	load_RSA_private_key(buffer_dec_private_key_1, length_enc_private_key_1, privateKey1);
	load_RSA_private_key(buffer_dec_private_key_2, length_enc_private_key_2, privateKey2);
	load_RSA_private_key(buffer_dec_private_key_3, length_enc_private_key_3, privateKey3);

	unsigned char* buffer_txt_file = nullptr;
	int length_txt_file = 0;
	if (!read_all_file("in.txt", buffer_txt_file, length_txt_file)) {
		cout << "Error loading in.txt" << endl;
		return 1;
	}

	unsigned char* eSignBytes = nullptr;
	int lengthSig = 0;
	if (!read_all_file("eSign.sig", eSignBytes, lengthSig)) {
		cout << "Error loading eSign.sig" << endl;
		return 1;
	}

	unsigned char signature1[128], signature2[128], signature3[128];
	RSA_signature(buffer_txt_file, length_txt_file, privateKey1, signature1);
	RSA_signature(buffer_txt_file, length_txt_file, privateKey2, signature2);
	RSA_signature(buffer_txt_file, length_txt_file, privateKey3, signature3);

	if (memcmp(eSignBytes, signature1, lengthSig) == 0) {
		printf("fis1");
	}
	else if (memcmp(eSignBytes, signature2, lengthSig) == 0) {
		printf("fis2");
	}
	else if (memcmp(eSignBytes, signature3, lengthSig) == 0) {
		printf("fis3");
	}
	else
	{
		printf("No matches.");
	}

}

