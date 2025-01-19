#pragma warning(disable : 4996)

#include <iostream>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <fstream>
#include <iomanip> 
#include <string>
#include <sstream>

using namespace std;

class Cipher {
public:
    static const unsigned char ALGO_AES_CBC = 1;
    static const unsigned char ALGO_RSA_PKCS1 = 2;
    static const unsigned char MODE_ENCRYPT = 1;
    static const unsigned char MODE_DECRYPT = 2;

    unsigned char algorithm;

    Cipher(unsigned char algo) : algorithm(algo) {}

    static Cipher* create_instance(unsigned char algo);
};

class AESCBCCipher : public Cipher {
private:
    AES_KEY aes_key;
    unsigned char ivec[16];

public:
    AESCBCCipher() : Cipher(ALGO_AES_CBC) {}

    void init_cipher(unsigned char* user_key, unsigned short bit_key_length,
        unsigned short array_key_offset, unsigned char* iv,
        unsigned short array_iv_offset, unsigned char mode) {
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
    RSACipher() : Cipher(ALGO_RSA_PKCS1), rsa_key_pair(RSA_new()) {}

    int generate_key_pair(int bit_modulus_length, unsigned long public_exp) {
        BIGNUM* bne = BN_new();
        if (!BN_set_word(bne, public_exp)) {
            return -1;
        }

        if (!RSA_generate_key_ex(rsa_key_pair, bit_modulus_length, bne, nullptr)) {
            return -1;
        }

        BN_free(bne);
        return 1;
    }

    unsigned char* public_encrypt(unsigned char* in_buffer, unsigned short byte_in_length,
        unsigned short in_offset, unsigned short* byte_out_length) {
        int rsa_size = RSA_size(rsa_key_pair);
        unsigned char* encrypted = new unsigned char[rsa_size];

        int result = RSA_public_encrypt(byte_in_length, in_buffer + in_offset, encrypted,
            rsa_key_pair, RSA_PKCS1_PADDING);

        if (result == -1) {
            delete[] encrypted;
            return nullptr;
        }

        *byte_out_length = result;
        return encrypted;
    }

    ~RSACipher() {
        RSA_free(rsa_key_pair);
    }
};

// Factory Method Implementation
Cipher* Cipher::create_instance(unsigned char algo) {
    if (algo == ALGO_AES_CBC) {
        return new AESCBCCipher();
    }
    else if (algo == ALGO_RSA_PKCS1) {
        return new RSACipher();
    }
    return nullptr;
}

std::string to_hex(const unsigned char* data, size_t length) {
    std:ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    //oss << "\n";
    return oss.str();
}

int main() {
    // 1. Create AES-CBC Cipher instance
    Cipher* aes_cipher = Cipher::create_instance(Cipher::ALGO_AES_CBC);

    // 2. Initialize AES-CBC Cipher
    unsigned char key[16] = { 0 }; // Example key
    unsigned char iv[16] = { 0 };  // Example IV
    static_cast<AESCBCCipher*>(aes_cipher)->init_cipher(key, 128, 0, iv, 0, Cipher::MODE_ENCRYPT);

    // 3. Create RSA Cipher instance
    Cipher* rsa_cipher = Cipher::create_instance(Cipher::ALGO_RSA_PKCS1);

    // 4. Generate RSA Key Pair
    if (static_cast<RSACipher*>(rsa_cipher)->generate_key_pair(2048, RSA_F4) != 1) {
        std::cerr << "Failed to generate RSA key pair." << std::endl;
        return 1;
    }

    // 5. Encrypt Passwords from "wordlist.txt"
    std::ifstream inFile("wordlist.txt");
    std::ofstream outFile("enclist.txt", std::ios::trunc);

    if (!inFile.is_open()) {
        std::cerr << "Error opening wordlist.txt" << std::endl;
        return 1;
    }
    if (!outFile.is_open()) {
        std::cerr << "Error opening enclist.txt" << std::endl;
        return 1;
    }

    std::string password;
    while (getline(inFile, password)) {
        unsigned short encrypted_length;
        unsigned char* encrypted = static_cast<RSACipher*>(rsa_cipher)->public_encrypt(
            (unsigned char*)password.c_str(), password.size(), 0, &encrypted_length
        );

        if (encrypted) {
            // Convert to hex and write to file
            outFile << to_hex(encrypted, encrypted_length) << std::endl;
            delete[] encrypted;
        }
    }

    // Close files
    inFile.close();
    outFile.close();

    // Clean up
    delete aes_cipher;
    delete rsa_cipher;

    std::cout << "Encryption completed. Results saved in enclist.txt." << std::endl;
    return 0;
}

