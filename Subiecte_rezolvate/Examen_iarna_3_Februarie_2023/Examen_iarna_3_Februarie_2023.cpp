#pragma warning(disable : 4996)
#include <iostream>
#include <fstream>
#include <iomanip> 
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

using namespace std;

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
void calculate_hash(char* input, size_t input_size, unsigned char* outputHash) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_size);
	SHA256_Final(outputHash, &ctx);
}
void AES_CBC_encrypt(const unsigned char *inputKey, size_t keySize, unsigned char *IV, char *plaintext, size_t plaintextLen, unsigned char* ciphertext) {

	AES_KEY aes_key;
	AES_set_encrypt_key(inputKey, keySize, &aes_key);

	AES_cbc_encrypt((unsigned char *)plaintext, ciphertext, plaintextLen, &aes_key, IV, AES_ENCRYPT);
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
	//Subiectul 1

	//// scris in fisier cu ofstream
	ofstream outFile("hashes.txt");
	if (!outFile) {
		printf("hashes.txt file cannot be open or created");
	}
	outFile.clear();
	////	

	FILE* f = NULL;
	FILE* g = NULL;
	errno_t errR, err;
	char buffer[256], *pb;
	SHA_CTX ctx;

	errR = fopen_s(&f, "wordlist.txt", "rb");

	if (errR == 0) {
		while (1) {
			pb = fgets(buffer, sizeof(buffer), f);
			buffer[strcspn(buffer, "\r\n")] = 0;      ///atentie aici daca are si \r!!!!

			unsigned char hash[SHA256_DIGEST_LENGTH];
			calculate_hash(buffer, strlen(buffer), hash);

			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
				outFile << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
			}
			outFile << "\n";

			if (feof(f)) {
				break;
			}
			memset(buffer, 0, sizeof(buffer));
		}
		fclose(f);
		outFile.close();
	}
	else {
		printf("File cannot be open or it is missing.");
	}

	//Subiectul 2
	unsigned char *fileContent;
	int fileContentLen;
	if (!read_all_file("aes-cbc.bin", fileContent, fileContentLen)) {
		cout << "aes-cbc.bin" << endl;
		return 1;
	}

	unsigned char AES_key[32], IV[16];
	memcpy(IV, fileContent, 16);				//cheia
	memcpy(AES_key, fileContent + 16, 32);		//IV-ul

	ofstream outFileEncHashes("enc-sha256.txt");
	if (!outFileEncHashes) {
		printf("enc-sha256.txt file cannot be open or created");
	}
	outFileEncHashes.clear();

	err = fopen_s(&g, "hashes.txt", "rb");
	if (errR == 0) {
		while (1) {
			pb = fgets(buffer, sizeof(buffer), g);
			buffer[strcspn(buffer, "\r\n")] = 0;      ///atentie aici daca are si \r!!!!
			int bufferLen = strlen(buffer);

			unsigned char hashEnc[32*8];
			AES_CBC_encrypt(AES_key, (sizeof(AES_key) * 8), IV, buffer, bufferLen, hashEnc);
		
			for (int i = 0; i < 32; i++) {
				outFileEncHashes << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)hashEnc[i];
			}
			outFileEncHashes << "\n";

			if (feof(g)) {
				break;
			}
			memset(buffer, 0, sizeof(buffer));
		}
		fclose(g);
		outFileEncHashes.close();
	}
	else {
		printf("File cannot be open or it is missing.");
	}

	//Subiectul 3
	unsigned char *enc_sha_fileContent;
	int enc_sha_fileContentLen;
	if (!read_all_file("enc-sha256.txt", enc_sha_fileContent, enc_sha_fileContentLen)) {
		cout << "enc-sha256.txt file cannot be open" << endl;
		return 1;
	}

	RSA *rsa_kp;
	RSA *rsa_private, *rsa_public;

	rsa_kp = RSA_generate_key(1024, 65535, NULL, NULL);
	RSA_check_key(rsa_kp); // validate the just created RSA key pair

	FILE* k = fopen("rsa-key.pem", "w+");
	PEM_write_RSAPrivateKey(k, rsa_kp, NULL, NULL, 0, NULL, NULL); // save the private key components in PEM format file
	PEM_write_RSAPublicKey(k, rsa_kp); // save the public key components in PEM format file
	fclose(k);

	RSA_free(rsa_kp);

	FILE* fprivateRead = fopen("rsa-key.pem", "r");
	rsa_private = PEM_read_RSAPrivateKey(fprivateRead, NULL, NULL, NULL);
	fclose(fprivateRead);

	int rsa_size = RSA_size(rsa_private);
	unsigned char* rsa_signature = (unsigned char*)malloc(rsa_size);
	size_t siglen = 0;
	RSA_sign_message(enc_sha_fileContent, enc_sha_fileContentLen, rsa_private, rsa_signature, &siglen);
	RSA_free(rsa_private);

	//verificare
	FILE* fpublicRead = fopen("rsa-key.pem", "r");
	rsa_public = PEM_read_RSAPublicKey(fpublicRead, NULL, NULL, NULL);
	fclose(fpublicRead);

	unsigned char output[32];
	RSA_public_decrypt(siglen, rsa_signature, output, rsa_public, RSA_PKCS1_PADDING);

	int result = memcmp(output, enc_sha_fileContent, sizeof(SHA256_DIGEST_LENGTH));
	if (result) {
		printf("Wrong signature!\n");
	}
	else {
		printf("Signature has been verified!\n");
	}


}

