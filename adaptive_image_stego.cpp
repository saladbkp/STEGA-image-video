#include "adaptive_image_stego.hpp"
#include "crypto.hpp"

#include <opencv2/opencv.hpp>
#include <vector>
#include <iostream>
#include <cstdint>


namespace imgstego {

    static std::vector<uint8_t> stringToBytes(const std::string& s) {
        return std::vector<uint8_t>(s.begin(), s.end());
    }

    static std::string bytesToString(const std::vector<uint8_t>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }

    // 根据 Canny edge map 决定嵌入 bit 数
    // 0 = smooth → 4 bits
    // 255 = edge  → 1 bit
    static int bitsForPixel(uint8_t edgeVal) {
        if (edgeVal > 200)
            return 1;   // high texture
        return 4;       // smooth region
    }

    bool embedTextAdaptive(const std::string& coverImagePath,
                           const std::string& stegoImagePath,
                           const std::string& message)
    {
        cv::Mat img = cv::imread(coverImagePath, cv::IMREAD_COLOR);
        if (img.empty()) {
            std::cerr << "[adaptive embed] Failed to load image: " << coverImagePath << std::endl;
            return false;
        }

        // Edge map
        cv::Mat gray, edges;
        cv::cvtColor(img, gray, cv::COLOR_BGR2GRAY);
        cv::Canny(gray, edges, 100, 200);

        std::vector<uint8_t> msgBytes = stringToBytes(message);
        uint32_t msgLen = msgBytes.size();

        // 计算 totalBits
        size_t totalBits = 32 + msgLen * 8;

        // 计算可用容量
        size_t capacityBits = 0;

        for (int y = 0; y < img.rows; y++) {
            for (int x = 0; x < img.cols; x++) {
                capacityBits += bitsForPixel(edges.at<uint8_t>(y, x));
            }
        }

        if (totalBits > capacityBits) {
            std::cerr << "[adaptive embed] Not enough capacity: need "
                      << totalBits << " bits but only " << capacityBits << "\n";
            return false;
        }

        // Build bitstream
        std::vector<uint8_t> bits;
        bits.reserve(totalBits);

        // Length header (32-bit)
        for (int i = 31; i >= 0; i--) {
            bits.push_back((msgLen >> i) & 1);
        }

        for (uint8_t byte : msgBytes) {
            for (int i = 7; i >= 0; i--) {
                bits.push_back((byte >> i) & 1);
            }
        }

        size_t bitIndex = 0;

        for (int y = 0; y < img.rows && bitIndex < bits.size(); y++) {
            for (int x = 0; x < img.cols && bitIndex < bits.size(); x++) {

                int bitsHere = bitsForPixel(edges.at<uint8_t>(y, x));
                cv::Vec3b &pix = img.at<cv::Vec3b>(y, x);

                // embed into Blue channel first
                uint8_t &p = pix[0];

                uint8_t mask = (1 << bitsHere) - 1;
                uint8_t val = 0;

                for (int b = 0; b < bitsHere && bitIndex < bits.size(); b++) {
                    val |= (bits[bitIndex++] << (bitsHere - 1 - b));
                }

                p = (p & ~mask) | (val & mask);
            }
        }

        cv::imwrite(stegoImagePath, img);
        std::cout << "[adaptive embed] Done. Saved: " << stegoImagePath << std::endl;
        return true;
    }


    bool extractTextAdaptive(const std::string& stegoImagePath,
                             std::string& outMessage)
    {
        cv::Mat img = cv::imread(stegoImagePath);
        if (img.empty()) {
            std::cerr << "[adaptive extract] Failed to load " << stegoImagePath << "\n";
            return false;
        }

        // Rebuild edge map (same logic)
        cv::Mat gray, edges;
        cv::cvtColor(img, gray, cv::COLOR_BGR2GRAY);
        cv::Canny(gray, edges, 100, 200);

        std::vector<uint8_t> bits;

        // extract bits
        for (int y = 0; y < img.rows; y++) {
            for (int x = 0; x < img.cols; x++) {

                int bitsHere = bitsForPixel(edges.at<uint8_t>(y, x));
                uint8_t p = img.at<cv::Vec3b>(y, x)[0];

                for (int b = bitsHere - 1; b >= 0; b--) {
                    bits.push_back((p >> b) & 1);
                }
            }
        }

        if (bits.size() < 32) {
            std::cerr << "[adaptive extract] Not enough bits.\n";
            return false;
        }

        uint32_t msgLen = 0;
        size_t idx = 0;

        for (int i = 0; i < 32; i++) {
            msgLen = (msgLen << 1) | bits[idx++];
        }

        size_t needed = 32 + msgLen * 8;
        if (bits.size() < needed) {
            std::cerr << "[adaptive extract] Not enough bits for content.\n";
            return false;
        }

        std::vector<uint8_t> bytes;
        bytes.reserve(msgLen);

        for (uint32_t b = 0; b < msgLen; b++) {
            uint8_t cur = 0;
            for (int i = 0; i < 8; i++) {
                cur = (cur << 1) | bits[idx++];
            }
            bytes.push_back(cur);
        }

        outMessage = bytesToString(bytes);
        return true;
    }

    bool embedTextAdaptiveEncrypted(const std::string& coverImagePath,
                                    const std::string& stegoImagePath,
                                    const std::string& plaintext,
                                    const std::string& password)
    {
        std::vector<uint8_t> blob;
        if (!crypto::encryptAES256_PBKDF2(plaintext, password, blob)) {
            std::cerr << "[adaptive encrypt] encryption failed\n";
            return false;
        }

        // 把二进制 blob 包装成 string（可以包含 \0）
        std::string encData(reinterpret_cast<const char*>(blob.data()), blob.size());

        return embedTextAdaptive(coverImagePath, stegoImagePath, encData);
    }

    bool extractTextAdaptiveEncrypted(const std::string& stegoImagePath,
                                      const std::string& password,
                                      std::string& outPlaintext)
    {
        std::string encStr;
        if (!extractTextAdaptive(stegoImagePath, encStr)) {
            std::cerr << "[adaptive decrypt] extract adaptive failed\n";
            return false;
        }

        std::vector<uint8_t> blob(encStr.begin(), encStr.end());

        if (!crypto::decryptAES256_PBKDF2(blob, password, outPlaintext)) {
            std::cerr << "[adaptive decrypt] AES decrypt failed\n";
            return false;
        }

        return true;
    }


}
