#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace crypto {

    // 把 plaintext 用 password 加密，结果放在 outBlob
    // outBlob 是包含 header + salt + ciphertext 的二进制数据
    bool encryptAES256_PBKDF2(const std::string& plaintext,
                              const std::string& password,
                              std::vector<uint8_t>& outBlob);

    // 从 blob 中用 password 解密，得到 plaintext
    bool decryptAES256_PBKDF2(const std::vector<uint8_t>& blob,
                              const std::string& password,
                              std::string& outPlaintext);
}

#endif
