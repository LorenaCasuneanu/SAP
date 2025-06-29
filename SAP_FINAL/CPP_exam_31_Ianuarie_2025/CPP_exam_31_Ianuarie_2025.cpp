#pragma warning(disable : 4996)

#include <iostream>
#include <fstream>
#include <string>
#include <openssl/sha.h>
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
void compune_hash(const char* input, size_t input_len, unsigned char* outputHash)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(outputHash, &ctx);
}
int main()
{
	unsigned char iv[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char* signature;
	int signature_len = 0;

	if (!read_all_file("signature.sig", signature, signature_len))
	{
		cout << "Error loading signature" << endl;
		return 1;
	}

	RSA *rsa_pub;

	FILE *fpublic = fopen("RSAKey.pem", "r");
	rsa_pub = PEM_read_RSAPublicKey(fpublic, NULL, NULL, NULL);
	fclose(fpublic);

	unsigned char message_digest[SHA256_DIGEST_LENGTH];
	RSA_public_decrypt(signature_len, signature, message_digest, rsa_pub, RSA_PKCS1_PADDING);

	string salt = "ISMsalt";
	string line;
	size_t line_num = 1;

	ifstream wordfile("wordlist.txt");
	while (getline(wordfile, line))
	{
		string saltedWord = line + salt;
		unsigned char lineHashed[SHA256_DIGEST_LENGTH];

		compune_hash(saltedWord.c_str(), saltedWord.length(), lineHashed);
		if (memcmp(lineHashed, message_digest, SHA256_DIGEST_LENGTH) == 0)
		{
			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
				printf("%02X", message_digest[i]);
			}
			printf("\n");

			printf("The word is: %s and the line number is %d", line.c_str(), line_num);

			AES_KEY aes_key;

			unsigned char* encrypted_word = nullptr;
			unsigned char partial_block = line.length() % AES_BLOCK_SIZE ? 1 : 0;
			unsigned char ciphertext_blocks = line.length() / AES_BLOCK_SIZE + partial_block;
			encrypted_word = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

			AES_set_encrypt_key(message_digest, SHA256_DIGEST_LENGTH * 8, &aes_key);
			AES_cbc_encrypt((const unsigned char*)line.c_str(), encrypted_word, line.length(), &aes_key, iv, AES_ENCRYPT);

			ofstream wordEncrypted("word.enc");
			for (int i = 0; i < ciphertext_blocks * AES_BLOCK_SIZE; i++) {
				wordEncrypted << encrypted_word[i];
			}

		}
		line_num++;
	}
}


