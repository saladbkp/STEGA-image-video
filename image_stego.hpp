#ifndef IMAGE_STEGO_HPP
#define IMAGE_STEGO_HPP

#include <string>

// 基础 LSB：不加自适应、不加加密，只是先跑通流程
namespace imgstego {

    // 把 message 藏到 coverImage -> 生成 stegoImage
    bool embedTextLSB(const std::string& coverImagePath,
                      const std::string& stegoImagePath,
                      const std::string& message);

    // 从 stegoImage 提取 message
    bool extractTextLSB(const std::string& stegoImagePath,
                        std::string& outMessage);

}

#endif // IMAGE_STEGO_HPP
