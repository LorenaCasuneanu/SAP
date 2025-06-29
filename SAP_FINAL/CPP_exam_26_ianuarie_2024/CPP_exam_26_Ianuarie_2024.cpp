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

void compute_hash(const char* input, size_t input_len, unsigned char* outputHash)
{
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
	//Exer 1
	ifstream infileName("name.txt");
	FILE* oufileNameEnc = fopen("enc_name.aes", "wb+");
	unsigned char hash[SHA256_DIGEST_LENGTH];
	string line;

	getline(infileName, line);
	compute_hash(line.c_str(), line.length(), hash);

	printf("\nSHA256 = ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02X", hash[i]);
	}
	printf("\n");

	//Exer 2
	unsigned char IV[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x07, 0x06, 0x05, 0x00, 0x00, 0xFF, 0xFF };   //DACA VREAU DECRYPT --> SA FAC COPIE LA IV CA SE MODIFICA	int iv_lenght = 0;
	
	unsigned char* aes_key_bytes = nullptr;
	int aes_key_lenght = 0;
	if (!read_all_file("aes.key", aes_key_bytes, aes_key_lenght))
	{
		cout << "Error loading aes.key" << endl;
		return 1;
	}


	unsigned char* encrypted_name = nullptr;
	unsigned char partial_block = line.length() % AES_BLOCK_SIZE ? 1 : 0;
	unsigned char ciphertext_blocks = line.length() / AES_BLOCK_SIZE + partial_block;
	encrypted_name = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

	AES_KEY aes_key;
	AES_set_encrypt_key(aes_key_bytes, aes_key_lenght * 8, &aes_key);
	AES_cbc_encrypt((const unsigned char*)line.c_str(), encrypted_name, line.length(), &aes_key, IV, AES_ENCRYPT );

	fwrite(encrypted_name, ciphertext_blocks * AES_BLOCK_SIZE, 1, oufileNameEnc); // save the signature into signature.sig

	//Exec 3
	RSA *rsa_kp = nullptr;
	rsa_kp = RSA_generate_key(1024, 65535, NULL, NULL);

	if (!RSA_check_key(rsa_kp))
		return 0; // validate the just created RSA key pair. Returns 1 if RSA valid

	int rsa_size = RSA_size(rsa_kp); 

	FILE* fpublic = fopen("RSAPublicKey.pem", "w+");
	PEM_write_RSAPublicKey(fpublic, rsa_kp); // save the public key components in PEM format file
	fclose(fpublic);

	unsigned char hashOfEncryptedFile[SHA256_DIGEST_LENGTH];
	compute_hash((const char*) encrypted_name, ciphertext_blocks * AES_BLOCK_SIZE, hashOfEncryptedFile);

	unsigned char* rsa_signature = (unsigned char*)malloc(rsa_size);
	RSA_private_encrypt(SHA256_DIGEST_LENGTH, hashOfEncryptedFile, rsa_signature, rsa_kp, RSA_PKCS1_PADDING); // the signature generated and saved into rsa_signature
	
	FILE* fsign = fopen("digital.sign", "wb+");
	fwrite(rsa_signature, rsa_size, 1, fsign);
	fclose(fsign);

	// signature verification
	unsigned char* signature = nullptr;
	int signature_lenght = 0;
	if (!read_all_file("digital.sign", signature, signature_lenght))
	{
		cout << "Error loading signature" << endl;
		return 1;
	}
	unsigned char originalEncMessage[SHA256_DIGEST_LENGTH];
	RSA_public_decrypt(signature_lenght, signature, originalEncMessage, rsa_kp, RSA_PKCS1_PADDING);

	int result = memcmp(originalEncMessage, hashOfEncryptedFile, SHA256_DIGEST_LENGTH);
	
	if (result)
	{
		printf("Wrong signature!\n");
	}
	else
	{
		printf("Signature has beed verified!\n");
	}

	RSA_free(rsa_kp);
	free(rsa_signature);


}


