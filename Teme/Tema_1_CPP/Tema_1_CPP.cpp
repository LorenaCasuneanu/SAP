#include <iostream>
#include <fstream>
#include <iomanip> 
#include <openssl/sha.h>

#pragma warning(disable : 4996)
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

int main()
{
	string expectedHash = "2e1a480670e31a5d015e28de043136b62e762d29";
	unsigned char expectedHashBytes[SHA_DIGEST_LENGTH];
	hextext2bin(expectedHash, expectedHashBytes);

	//// scris in fisier cu ofstream
	ofstream outFile("pass_SHA1.txt", std::ofstream::binary);
	if (!outFile) {
		printf("pass_SHA1.txt file cannot be open or created");
	}
	////	

	FILE* f = NULL;
	errno_t errR;
	char buffer[256], *pb;
	SHA_CTX ctx;

	errR = fopen_s(&f, "10-million-password-list-top-1000000.txt", "rb");

	if (errR == 0) {
		while (1) {
			pb = fgets(buffer, sizeof(buffer), f);

			buffer[strcspn(buffer, "\n")] = 0;

			unsigned char hash[SHA_DIGEST_LENGTH];
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, buffer, strlen(buffer));
			SHA1_Final(hash, &ctx);
			for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
				outFile << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
			}
			outFile << "\n";

			if (memcmp(hash, expectedHashBytes, SHA_DIGEST_LENGTH) == 0) {
				printf("The password is: %s \n", buffer);
				printf("The SHA1 password: ");
				for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
					printf("%02X", buffer[i]);
				}
				//break;       --> nu mai e nevoie aici pt ca vreau sa scriu toate hashs
			}

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
}

