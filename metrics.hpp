#ifndef METRICS_HPP
#define METRICS_HPP

#include <opencv2/opencv.hpp>
#include <string>

namespace metrics {

    double computePSNR(const cv::Mat& I1, const cv::Mat& I2);

    double computeSSIM(const cv::Mat& img1, const cv::Mat& img2);

    // BER for extracted vs original text
    double computeBER(const std::string& original, const std::string& extracted);
}

#endif
