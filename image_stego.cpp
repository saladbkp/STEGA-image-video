#include "image_stego.hpp"

#include <opencv2/opencv.hpp>
#include <vector>
#include <iostream>

namespace imgstego {

    // string <-> bytes 工具
    static std::vector<uint8_t> stringToBytes(const std::string& s) {
        return std::vector<uint8_t>(s.begin(), s.end());
    }

    static std::string bytesToString(const std::vector<uint8_t>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }

    bool embedTextLSB(const std::string& coverImagePath,
                      const std::string& stegoImagePath,
                      const std::string& message)
    {
        cv::Mat img = cv::imread(coverImagePath, cv::IMREAD_COLOR);
        if (img.empty()) {
            std::cerr << "[embed] Failed to load image: " << coverImagePath << std::endl;
            return false;
        }

        std::vector<uint8_t> msgBytes = stringToBytes(message);
        uint32_t msgLen = static_cast<uint32_t>(msgBytes.size());

        // 总 bit 数：32 bit 存长度 + 内容 bit
        size_t totalBits = 32 + msgLen * 8;
        size_t capacityBits = img.total() * 3; // 每个像素 3 个通道，每通道 1bit

        if (totalBits > capacityBits) {
            std::cerr << "[embed] Message too long. Need " << totalBits
                      << " bits, capacity = " << capacityBits << " bits.\n";
            return false;
        }

        // 构造 bit 流
        std::vector<uint8_t> bits;
        bits.reserve(totalBits);

        // 长度（32 bit，大端）
        for (int i = 31; i >= 0; --i) {
            bits.push_back((msgLen >> i) & 1);
        }

        // 内容
        for (uint8_t byte : msgBytes) {
            for (int i = 7; i >= 0; --i) {
                bits.push_back((byte >> i) & 1);
            }
        }

        size_t bitIndex = 0;
        for (int y = 0; y < img.rows && bitIndex < bits.size(); ++y) {
            for (int x = 0; x < img.cols && bitIndex < bits.size(); ++x) {
                cv::Vec3b& pixel = img.at<cv::Vec3b>(y, x);
                for (int c = 0; c < 3 && bitIndex < bits.size(); ++c) {
                    uint8_t bit = bits[bitIndex++];
                    pixel[c] = (pixel[c] & 0xFE) | bit; // 清 LSB 再写
                }
            }
        }

        if (!cv::imwrite(stegoImagePath, img)) {
            std::cerr << "[embed] Failed to save stego image: " << stegoImagePath << std::endl;
            return false;
        }

        std::cout << "[embed] Done. Saved: " << stegoImagePath << std::endl;
        return true;
    }

    bool extractTextLSB(const std::string& stegoImagePath,
                        std::string& outMessage)
    {
        cv::Mat img = cv::imread(stegoImagePath, cv::IMREAD_COLOR);
        if (img.empty()) {
            std::cerr << "[extract] Failed to load image: " << stegoImagePath << std::endl;
            return false;
        }

        std::vector<uint8_t> bits;
        bits.reserve(img.total() * 3);

        // 把所有 LSB 读出来
        for (int y = 0; y < img.rows; ++y) {
            for (int x = 0; x < img.cols; ++x) {
                const cv::Vec3b& pixel = img.at<cv::Vec3b>(y, x);
                for (int c = 0; c < 3; ++c) {
                    bits.push_back(pixel[c] & 1);
                }
            }
        }

        if (bits.size() < 32) {
            std::cerr << "[extract] Not enough bits for length header.\n";
            return false;
        }

        // 前 32 bit 还原长度（大端）
        uint32_t msgLen = 0;
        for (int i = 0; i < 32; ++i) {
            msgLen = (msgLen << 1) | bits[i];
        }

        size_t neededBits = 32 + msgLen * 8;
        if (bits.size() < neededBits) {
            std::cerr << "[extract] Not enough bits for full message. "
                      << "Length = " << msgLen << " bytes.\n";
            return false;
        }

        // 还原内容
        std::vector<uint8_t> msgBytes;
        msgBytes.reserve(msgLen);

        size_t bitPos = 32;
        for (uint32_t b = 0; b < msgLen; ++b) {
            uint8_t curByte = 0;
            for (int i = 0; i < 8; ++i) {
                curByte = (curByte << 1) | bits[bitPos++];
            }
            msgBytes.push_back(curByte);
        }

        outMessage = bytesToString(msgBytes);
        return true;
    }

} // namespace imgstego
