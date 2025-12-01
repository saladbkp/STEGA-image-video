#include "metrics.hpp"
#include <cmath>
#include <iostream>

namespace metrics {

    // --- PSNR ---
    double computePSNR(const cv::Mat& I1, const cv::Mat& I2)
    {
        cv::Mat s1;
        absdiff(I1, I2, s1);
        s1.convertTo(s1, CV_32F);
        s1 = s1.mul(s1);

        cv::Scalar s = cv::sum(s1);
        double sse = s.val[0] + s.val[1] + s.val[2];

        if (sse <= 1e-10) return 100; // identical
        double mse = sse / (double)(I1.channels() * I1.total());
        double psnr = 10.0 * log10((255 * 255) / mse);
        return psnr;
    }


    // --- SSIM ---
    static double ssimSingleChannel(const cv::Mat& img1, const cv::Mat& img2)
    {
        double C1 = 6.5025, C2 = 58.5225;

        cv::Mat I1, I2;
        img1.convertTo(I1, CV_32F);
        img2.convertTo(I2, CV_32F);

        cv::Mat I1_2 = I1.mul(I1);
        cv::Mat I2_2 = I2.mul(I2);
        cv::Mat I1_I2 = I1.mul(I2);

        cv::Mat mu1, mu2;
        cv::GaussianBlur(I1, mu1, cv::Size(11, 11), 1.5);
        cv::GaussianBlur(I2, mu2, cv::Size(11, 11), 1.5);

        cv::Mat mu1_2 = mu1.mul(mu1);
        cv::Mat mu2_2 = mu2.mul(mu2);
        cv::Mat mu1_mu2 = mu1.mul(mu2);

        cv::Mat sigma1_2, sigma2_2, sigma12;

        cv::GaussianBlur(I1_2, sigma1_2, cv::Size(11, 11), 1.5);
        sigma1_2 -= mu1_2;

        cv::GaussianBlur(I2_2, sigma2_2, cv::Size(11, 11), 1.5);
        sigma2_2 -= mu2_2;

        cv::GaussianBlur(I1_I2, sigma12, cv::Size(11, 11), 1.5);
        sigma12 -= mu1_mu2;

        cv::Mat t1 = 2 * mu1_mu2 + C1;
        cv::Mat t2 = 2 * sigma12 + C2;
        cv::Mat t3 = t1.mul(t2);

        cv::Mat t4 = mu1_2 + mu2_2 + C1;
        cv::Mat t5 = sigma1_2 + sigma2_2 + C2;
        cv::Mat t6 = t4.mul(t5);

        cv::Mat ssim_map;
        divide(t3, t6, ssim_map);
        cv::Scalar mssim = mean(ssim_map);
        return mssim.val[0];
    }

    double computeSSIM(const cv::Mat& img1, const cv::Mat& img2)
    {
        std::vector<cv::Mat> ch1, ch2;
        cv::split(img1, ch1);
        cv::split(img2, ch2);

        double ssim_total = 0;
        for (int i = 0; i < 3; i++) {
            ssim_total += ssimSingleChannel(ch1[i], ch2[i]);
        }
        return ssim_total / 3.0;
    }

    // --- BER ---
    double computeBER(const std::string& original, const std::string& extracted)
    {
        if (original.size() != extracted.size()) {
            return 1.0; // 100% wrong
        }

        int bitErrors = 0;
        int totalBits = original.size() * 8;

        for (size_t i = 0; i < original.size(); i++) {
            uint8_t a = original[i];
            uint8_t b = extracted[i];

            uint8_t diff = a ^ b;
            bitErrors += __builtin_popcount(diff);
        }

        return (double)bitErrors / totalBits;
    }

}
