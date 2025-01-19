#include <iostream>
#include <fstream>
#include <iomanip> 
#include <string>
#include <openssl/aes.h>
#include <openssl/sha.h>
using namespace std;
#pragma warning(disable : 4996)

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


int main()
{
	unsigned char keyBytes[32];
	unsigned char ciphertext[48];

	//// scris in fisier cu ofstream
	ofstream outFile("C:/Users/nxf71449/source/repos/Tema_2_CPP/Tema_2_CPP/SHA256_Enc.txt", std::ofstream::binary);
	if (!outFile) {
		printf("SHA256_Enc.txt file cannot be open or created");
	}
	outFile.clear();
	////


	ifstream keyFile("C:/Users/nxf71449/source/repos/Tema_2_CPP/Tema_2_CPP/pass.key", std::ofstream::binary);
	if (!keyFile) {
		printf("pass.key file cannot be open");
	}
	else {
		string key;
		getline(keyFile, key);
		hextext2bin(key, keyBytes);
	}

	string buffer;
	ifstream file("C:/Users/nxf71449/source/repos/Tema_2_CPP/Tema_2_CPP/Accounts.txt");
	
	if (file.is_open()) {
		while (getline(file, buffer)) {
			size_t pos = buffer.find("=");
			if (pos != string::npos) {
				string hash = buffer.substr(pos + 2);
				
				unsigned char hashBytes[SHA256_DIGEST_LENGTH];
				hextext2bin(hash, hashBytes);

				AES_KEY aes_key;
				AES_set_encrypt_key(keyBytes, (sizeof(keyBytes) * 8), &aes_key);

				for (unsigned int i = 0; i < sizeof(hashBytes); i += 16)
					AES_encrypt(&hashBytes[i], &ciphertext[i], &aes_key);

				for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
					outFile << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
				}
				outFile << "\n";
			}
		}
		file.close();
	}
	else {
		// show message:
		std::cout << "Error opening file";
	}

}

