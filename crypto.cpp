#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <vector>
#include <iostream>
#include <cstring>

namespace crypto {

    static const int SALT_SIZE = 16;
    static const int KEY_SIZE  = 32; // 256 bit
    static const int IV_SIZE   = 16; // 128 bit (AES block size)
    static const int PBKDF2_ITER = 100000; // 可写进论文 NIST 推荐量级

    // blob 格式:
    // [ 'S','T','G','1' ] (4 bytes magic)
    // [ salt (16 bytes) ]
    // [ ciphertext (...) ]

    bool encryptAES256_PBKDF2(const std::string& plaintext,
                              const std::string& password,
                              std::vector<uint8_t>& outBlob)
    {
        outBlob.clear();

        // 生成随机 salt
        unsigned char salt[SALT_SIZE];
        if (RAND_bytes(salt, SALT_SIZE) != 1) {
            std::cerr << "[crypto] RAND_bytes salt failed\n";
            return false;
        }

        // 使用 PBKDF2 从 password + salt 派生 key + iv
        unsigned char keyiv[KEY_SIZE + IV_SIZE];
        if (PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                              salt, SALT_SIZE,
                              PBKDF2_ITER,
                              EVP_sha256(),
                              KEY_SIZE + IV_SIZE,
                              keyiv) != 1)
        {
            std::cerr << "[crypto] PBKDF2 failed\n";
            return false;
        }

        unsigned char key[KEY_SIZE];
        unsigned char iv[IV_SIZE];
        std::memcpy(key, keyiv, KEY_SIZE);
        std::memcpy(iv, keyiv + KEY_SIZE, IV_SIZE);

        // 准备加密
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "[crypto] EVP_CIPHER_CTX_new failed\n";
            return false;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            std::cerr << "[crypto] EVP_EncryptInit_ex failed\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        int cipherLen = plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc());
        std::vector<unsigned char> cipher(cipherLen);

        int outLen1 = 0;
        if (EVP_EncryptUpdate(ctx,
                              cipher.data(), &outLen1,
                              reinterpret_cast<const unsigned char*>(plaintext.data()),
                              plaintext.size()) != 1)
        {
            std::cerr << "[crypto] EVP_EncryptUpdate failed\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        int outLen2 = 0;
        if (EVP_EncryptFinal_ex(ctx, cipher.data() + outLen1, &outLen2) != 1) {
            std::cerr << "[crypto] EVP_EncryptFinal_ex failed\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);
        cipherLen = outLen1 + outLen2;
        cipher.resize(cipherLen);

        // 组装 blob: magic + salt + ciphertext
        outBlob.reserve(4 + SALT_SIZE + cipherLen);
        outBlob.push_back('S');
        outBlob.push_back('T');
        outBlob.push_back('G');
        outBlob.push_back('1');

        outBlob.insert(outBlob.end(), salt, salt + SALT_SIZE);
        outBlob.insert(outBlob.end(), cipher.begin(), cipher.end());

        return true;
    }

    bool decryptAES256_PBKDF2(const std::vector<uint8_t>& blob,
                              const std::string& password,
                              std::string& outPlaintext)
    {
        outPlaintext.clear();

        if (blob.size() < 4 + SALT_SIZE) {
            std::cerr << "[crypto] Blob too small\n";
            return false;
        }

        // 检查 magic
        if (!(blob[0] == 'S' && blob[1] == 'T' && blob[2] == 'G' && blob[3] == '1')) {
            std::cerr << "[crypto] Invalid magic header\n";
            return false;
        }

        unsigned char salt[SALT_SIZE];
        std::memcpy(salt, blob.data() + 4, SALT_SIZE);

        size_t cipherOffset = 4 + SALT_SIZE;
        size_t cipherLen = blob.size() - cipherOffset;
        if (cipherLen == 0) {
            std::cerr << "[crypto] No ciphertext\n";
            return false;
        }

        const unsigned char* cipherData = blob.data() + cipherOffset;

        // 重新派生 key + iv
        unsigned char keyiv[KEY_SIZE + IV_SIZE];
        if (PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                              salt, SALT_SIZE,
                              PBKDF2_ITER,
                              EVP_sha256(),
                              KEY_SIZE + IV_SIZE,
                              keyiv) != 1)
        {
            std::cerr << "[crypto] PBKDF2 failed\n";
            return false;
        }

        unsigned char key[KEY_SIZE];
        unsigned char iv[IV_SIZE];
        std::memcpy(key, keyiv, KEY_SIZE);
        std::memcpy(iv, keyiv + KEY_SIZE, IV_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "[crypto] EVP_CIPHER_CTX_new failed\n";
            return false;
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            std::cerr << "[crypto] EVP_DecryptInit_ex failed\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        std::vector<unsigned char> plain(cipherLen + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int outLen1 = 0;

        if (EVP_DecryptUpdate(ctx,
                              plain.data(), &outLen1,
                              cipherData, cipherLen) != 1)
        {
            std::cerr << "[crypto] EVP_DecryptUpdate failed\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        int outLen2 = 0;
        if (EVP_DecryptFinal_ex(ctx, plain.data() + outLen1, &outLen2) != 1) {
            std::cerr << "[crypto] EVP_DecryptFinal_ex failed (wrong password?)\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);

        int plainLen = outLen1 + outLen2;
        plain.resize(plainLen);

        outPlaintext.assign(reinterpret_cast<char*>(plain.data()), plainLen);
        return true;
    }

}
