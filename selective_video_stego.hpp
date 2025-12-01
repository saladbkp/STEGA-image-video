#ifndef SELECTIVE_VIDEO_STEGO_HPP
#define SELECTIVE_VIDEO_STEGO_HPP

#include <string>

namespace vdstego {

    // 静态帧比例（例如 0.3 = 30% 最静的帧用于嵌入）
    constexpr double DEFAULT_STATIC_RATIO = 0.3;

    // 按静态帧选择嵌入「任意文件」(例如 secret_small.mp4)
    bool embedFileSelective(const std::string& coverVideoPath,
                            const std::string& stegoVideoPath,
                            const std::string& secretFilePath,
                            double staticRatio = DEFAULT_STATIC_RATIO);

    // 从静态帧中提取「任意文件」
    bool extractFileSelective(const std::string& stegoVideoPath,
                              const std::string& outputFilePath,
                              double staticRatio = DEFAULT_STATIC_RATIO);

    // 如果你想做文字版，也可以：
    bool embedTextSelective(const std::string& coverVideoPath,
                            const std::string& stegoVideoPath,
                            const std::string& message,
                            double staticRatio = DEFAULT_STATIC_RATIO);

    bool extractTextSelective(const std::string& stegoVideoPath,
                              std::string& outMessage,
                              double staticRatio = DEFAULT_STATIC_RATIO);
}

#endif
