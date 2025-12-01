#ifndef VIDEO_STEGO_HPP
#define VIDEO_STEGO_HPP

#include <string>

namespace vdstego {

    // 之前的：文字藏进视频
    bool embedTextInVideo(const std::string& coverVideoPath,
                          const std::string& stegoVideoPath,
                          const std::string& message);
    bool embedTextInVideoSelective(const std::string& coverVideoPath,
                                   const std::string& stegoVideoPath,
                                   const std::string& message,
                                   double motionThreshold = 3.0);

    bool extractTextFromVideo(const std::string& stegoVideoPath,
                              std::string& outMessage);
    bool extractTextFromVideoSelective(const std::string& stegoVideoPath,
                                       std::string& outMessage,
                                       double motionThreshold = 3.0);

    // 新的：文件（二进制）藏进视频 → 用于 video-in-video
    bool embedFileInVideo(const std::string& coverVideoPath,
                          const std::string& stegoVideoPath,
                          const std::string& secretFilePath);
    bool embedFileInVideoSelective(const std::string& coverVideoPath,
                                   const std::string& stegoVideoPath,
                                   const std::string& secretFilePath,
                                   double motionThreshold = 3.0);

    bool extractFileFromVideo(const std::string& stegoVideoPath,
                              const std::string& outputFilePath);
    bool extractFileFromVideoSelective(const std::string& stegoVideoPath,
                                       const std::string& outputFilePath,
                                       double motionThreshold = 3.0);

    // 视频质量指标
    bool computeVideoMetrics(const std::string& coverVideoPath,
                             const std::string& stegoVideoPath,
                             double& outPSNR,
                             double& outSSIM,
                             double& outSyncErrorFrames,
                             int sampleStride = 1,
                             bool computeVMAF = false,
                             double* outVMAF = nullptr);

    // 加密 payload（AES-256 + PBKDF2）
    bool embedTextInVideoEncrypted(const std::string& coverVideoPath,
                                   const std::string& stegoVideoPath,
                                   const std::string& message,
                                   const std::string& password);
    bool extractTextFromVideoEncrypted(const std::string& stegoVideoPath,
                                       const std::string& password,
                                       std::string& outMessage);
    bool embedFileInVideoEncrypted(const std::string& coverVideoPath,
                                   const std::string& stegoVideoPath,
                                   const std::string& secretFilePath,
                                   const std::string& password);
    bool extractFileFromVideoEncrypted(const std::string& stegoVideoPath,
                                       const std::string& password,
                                       const std::string& outputFilePath);
}

#endif
