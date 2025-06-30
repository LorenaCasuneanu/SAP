 
// !!!!!!!!! STRING -> BYTE []   cu    str.c_str() sau str.data()        (ultimul e fara null character la final)

// SCRIU INTR-UN FISIER TOTI BYTES DINTR-O DATA (MERGEM PENTRU SEMNATURA)
{
	FILE* signature = fopen("esign.sig", "w+");
	unsigned char* e_data = NULL;
	e_data = (unsigned char*)malloc(RSA_size(rsa_kp)); //RSA_size => 1024 bits/128 bytes
	fwrite(e_data, RSA_size(rsa_kp), 1, signature); // write the e-sign into the file
}

// SCRIU INTR-UN FISIER TOTI BYTES PE RAND IN FORMA DE HEX
{
		if (output != NULL) {
			for (int i = 0; i < output_lenght; i++) {
				outfile << std::hex << std::setw(2) << std::setfill('0') << (int)output[i];

			}
		}
		outfile << "\n";
}

//PRINT HASH in consola in HEX format
{ 
	printf("\nSHA256 = ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02X", hash[i]);
	}
	printf("\n");
}

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

// IAU BYTES dintru fisier si primii 16 sunt IV, urmatorii 32 sunt AES key bytes 
{
	unsigned char* AESbuffer = nullptr;
	int aesFileLenght = 0;
	read_all_file("aes-cbc.bin", AESbuffer, aesFileLenght);

	unsigned char aes_key_bytes[32], iv[16];
	memcpy(iv, AESbuffer, 16);
	memcpy(aes_key_bytes, AESbuffer + 16, 32);
}


// CALCULEAZA PENTRU FIECARE LINIE DIN FISIER HASH-ul SI-L SALVEAZA IN ALTA FISIER PE CARE O LINIE
{
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

}


// CITIRE DUPA UN ANUMIT CHARATER DINTR-UN FILE
{	
	size_t pos = buffer.find("=");
			if (pos != string::npos) {
				string hash = buffer.substr(pos + 2);
			}
}

// Compara doua arrays
{
	if (memcmp(eSignBytes, signature1, lengthSig) == 0) {
		printf("fis1");
	}
}


// Citeste tot continutul unui fisier
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

// Face AES_DECRYPT
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

// Incarca bytes pentru RSA private key intr-un PEM file si dupa citeste din el ca sa ia cheia bine intr-un obiect RSA
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

// face HASH 
void calculate_hash(const char* input, size_t input_len, unsigned char* outputHash) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(outputHash, &ctx);
}

// DIGITAL SIGNATURE --> face HASH si dupa encrypt cu PRIVATA RSA
void RSA_signature(unsigned char* input, size_t input_len, RSA* rsa_key, unsigned char* outputSigned) {

	unsigned char outputHash[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, input_len);
	SHA256_Final(outputHash, &ctx);

	RSA_private_encrypt(SHA256_DIGEST_LENGTH, outputHash, outputSigned, rsa_key, RSA_PKCS1_PADDING); // encryption for e-signature made by using the PRIVATE key
}
