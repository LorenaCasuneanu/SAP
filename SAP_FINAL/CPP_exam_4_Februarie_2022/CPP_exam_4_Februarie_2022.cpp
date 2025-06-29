// CPP_exam_4_Februarie_2022.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <iomanip>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>
#include <openssl/applink.c>


class Cipher {
public:
	static unsigned char ALGO_AES_CBC ;
	static unsigned char ALGO_RSA_PKCS1;
	static unsigned char MODE_ENCRYPT;
	static unsigned char MODE_DECRYPT;
	unsigned char algorithm;

	Cipher(unsigned char algo) : algorithm(algo) {};

	static Cipher create_instance(unsigned char algo) {
		if (algo == ALGO_AES_CBC || algo == ALGO_RSA_PKCS1) {
			return Cipher(algo);  // Valid algorithms
		}
		else
		{
			throw std::invalid_argument("Unsupported algorithm");
		}
	}

};

class AESECBCipher : public Cipher {
private:
	AES_KEY aes_key;
	unsigned char ivec[16];

public:
	AESECBCipher() : Cipher(ALGO_AES_CBC) {
		std::memset(ivec, 0, sizeof(ivec));
	}

	void init_cipher(unsigned char* user_key, unsigned short int bit_key_length, unsigned short array_key_offset, unsigned char* iv, unsigned short array_iv_offset, unsigned char mode) {
		memcpy(ivec, iv + array_iv_offset, 16);

		if (mode == MODE_ENCRYPT) {
			AES_set_encrypt_key(user_key + array_key_offset, bit_key_length, &aes_key);
		}
		else {
			AES_set_decrypt_key(user_key + array_key_offset, bit_key_length, &aes_key);
		}
	}
};

class RSACipher : public Cipher {
private:
	RSA* rsa_key_pair;

public:
	RSACipher() : Cipher(ALGO_RSA_PKCS1), rsa_key_pair(nullptr) {}

	int generate_key_pair(int bit_modulus_length, unsigned long public_exp) {
		rsa_key_pair = RSA_generate_key(bit_modulus_length, public_exp, NULL, NULL);
		
		if (RSA_check_key(rsa_key_pair)) {
			return 0; // validate the previous generated key pair
		}
		else {
			return 1;
		}
	}

	unsigned char * public_encrypt(unsigned char* in_buffer, unsigned short byte_in_length, unsigned short in_offset, unsigned short* byte_out_length) {
		
		*byte_out_length = 0;
		int key_size = RSA_size(rsa_key_pair); // RSA key size in number of bytes

		size_t chunks = byte_in_length / key_size;
		size_t last_chunk_size = byte_in_length % key_size;
		size_t total_chunks = chunks + last_chunk_size > 0 ? 1 : 0;
		unsigned char* out = NULL;
		out = (unsigned char*)malloc(total_chunks* key_size); // buffer with the ciphertext after encryption

		for (int i = 0; i<chunks; i++) {

			int ret = RSA_public_encrypt(byte_in_length, in_buffer + in_offset + i* key_size, out + i * key_size, rsa_key_pair, RSA_NO_PADDING); // encrypt one single full data block
			if (ret == -1) {
				free(out);
				return nullptr;
			}
			*byte_out_length += ret;
		}

		if (last_chunk_size != 0)
		{
			int ret = RSA_public_encrypt(byte_in_length, in_buffer + in_offset + chunks * key_size, out + chunks * key_size, rsa_key_pair, RSA_PKCS1_PADDING); // encrypt one single full data block
			if (ret == -1) {
				free(out);
				return nullptr;
			}
			*byte_out_length += ret;
		}

		return out;
	}
	~RSACipher() {
		if (rsa_key_pair) 
			RSA_free(rsa_key_pair);
	}
};

unsigned char Cipher::ALGO_AES_CBC = 1;
unsigned char Cipher::ALGO_RSA_PKCS1 = 2;
unsigned char Cipher::MODE_ENCRYPT = 0;
unsigned char Cipher::MODE_DECRYPT = 1;

int main()
{
	Cipher AESinstance = Cipher::create_instance(Cipher::ALGO_AES_CBC);
	Cipher RSAinstance = Cipher::create_instance(Cipher::ALGO_RSA_PKCS1);

	AESECBCipher aes;
	RSACipher rsa;

	unsigned char key[16] = { 0 };
	unsigned char iv[16] = { 0 };
	aes.init_cipher(key, 128, 0, iv, 0, Cipher::MODE_ENCRYPT);

	aes.init_cipher(key, 128, 0, iv, 0, Cipher::MODE_ENCRYPT);
	rsa.generate_key_pair(2048, 0x10001);

	std::ifstream infile("wordlist.txt");
	std::ofstream outfile("enclist.txt");

	std::string line;
	while (std::getline(infile, line)) {
		unsigned short output_lenght = 0;
		unsigned char *output;

		output = rsa.public_encrypt((unsigned char*)line.c_str(), line.length(), 0, &output_lenght);

		if (output != NULL) {
			for (int i = 0; i < output_lenght; i++) {
				outfile << std::hex << std::setw(2) << std::setfill('0') << (int)output[i];

			}
		}
		outfile << "\n";
		free(output);
	}
	infile.close();
	outfile.close();
}