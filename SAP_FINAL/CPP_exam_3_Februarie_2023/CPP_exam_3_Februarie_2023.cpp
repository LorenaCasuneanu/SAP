#pragma warning(disable : 4996)

#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

using namespace std;

void calculate_hash(const char* input, size_t input_len, unsigned char* outputHash) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(outputHash, &ctx);
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

int main()
{
	// Exer 1
	ifstream infile("wordlist.txt");
	ofstream outfile("hashes.txt");

	if (!infile) {
		printf("wordlist.txt file cannot be open or created");
	}
	if (!outfile) {
		printf("hashes.txt file cannot be open or created");
	}
	outfile.clear();

	string line;
	while (std::getline(infile, line)) {
		unsigned char finalDigest[SHA256_DIGEST_LENGTH];

		calculate_hash(line.c_str(), line.length(), finalDigest);

		if (finalDigest != NULL) {
			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
				outfile << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)finalDigest[i];
			}
		}
		outfile << "\n";

	}
	infile.close();
	outfile.close();

	// Exer 2
	unsigned char* AESbuffer = nullptr;
	int aesFileLenght = 0;
	read_all_file("aes-cbc.bin", AESbuffer, aesFileLenght);

	unsigned char aes_key_bytes[32], iv[16];
	memcpy(iv, AESbuffer, 16);
	memcpy(aes_key_bytes, AESbuffer + 16, 32);

	AES_KEY aes_key;
	AES_set_encrypt_key(aes_key_bytes, (sizeof(aes_key_bytes) * 8), &aes_key);

	ifstream infileHashes("hashes.txt");
	ofstream outfileEnc("enc-sha256.txt");

	
	if (!infileHashes) {
		printf("hashes.txt file cannot be open or created");
	}
	if (!outfileEnc) {
		printf("enc-sha256.txt file cannot be open or created");
	}
	outfileEnc.clear();


	string lineHash;
	while (getline(infileHashes, lineHash)) {
		
		unsigned char* ciphertext = NULL;

		unsigned char partial_block = lineHash.length() % AES_BLOCK_SIZE ? 1 : 0;
		unsigned char ciphertext_blocks = lineHash.length() / AES_BLOCK_SIZE + partial_block;
		ciphertext = (unsigned char*)malloc(lineHash.length() * AES_BLOCK_SIZE);

		AES_cbc_encrypt((const unsigned char*) lineHash.c_str(), ciphertext, lineHash.length(), &aes_key, iv, AES_ENCRYPT);

		if (ciphertext != NULL) {
			for (int i = 0; i < (unsigned int)(ciphertext_blocks * AES_BLOCK_SIZE); i++) {
				outfileEnc << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
			}
		}
		outfileEnc << "\n";
	}

	//Exer 3
	RSA *rsa_kp = nullptr;
	rsa_kp = RSA_generate_key(1024, 65535, NULL, NULL);
	
	 if (!RSA_check_key(rsa_kp))
		 return 0; // validate the just created RSA key pair. Returns 1 if RSA valid

	 FILE* k = fopen("rsa-key.pem", "w+");
	 FILE* signature = fopen("esign.sig", "w+");

	 PEM_write_RSAPrivateKey(k, rsa_kp, NULL, NULL, 0, NULL, NULL); // save the private key components in PEM format file
	 fclose(k);

	 unsigned char* enc_buffer = nullptr;
	 unsigned char enc_buffer_hash[SHA256_DIGEST_LENGTH];
	 int enc_buffer_lenght = 0;

	 unsigned char* e_data = NULL;
	 e_data = (unsigned char*)malloc(RSA_size(rsa_kp)); //RSA_size => 1024 bits/128 bytes

	 if (read_all_file("enc-sha256.txt", enc_buffer, enc_buffer_lenght))
	 {
		 calculate_hash((const char*) enc_buffer, enc_buffer_lenght, enc_buffer_hash);
		 RSA_private_encrypt(SHA256_DIGEST_LENGTH, enc_buffer_hash, e_data, rsa_kp, RSA_PKCS1_PADDING); // encryption for e-signature made by using the PRIVATE key
		 fwrite(e_data, RSA_size(rsa_kp), 1, signature); // write the e-sign into the file
	 }
	 RSA_free(rsa_kp);
}

