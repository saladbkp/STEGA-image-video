# Dual Stego (C++)

Quick notes and commands collected while building the image/video steganography tool. Updated: 27/11.

## Features
- Hide/extract text in images (PNG/JPEG); supports large text payloads via file input.
- Metrics: PSNR / SSIM for images; PSNR / SSIM / VMAF / sync error / FPS for video.
- Adaptive LSB with Canny-based bit selection for higher capacity with low distortion.
- AES-256 + PBKDF2 encryption for both image and video payloads.
- Video stego: text-in-video, file-in-video, encrypted variants, and selective-frame mode.
- NEW FEATURE: time encode, check decode time

## Build
```bash
g++ main.cpp image_stego.cpp adaptive_image_stego.cpp metrics.cpp crypto.cpp video_stego.cpp selective_video_stego.cpp -o stego `pkg-config --cflags --libs opencv4` -lcrypto
```

## Image text workflow (Step 1)
```bash
./stego embed image.png stego.png "hello_stego_test"
./stego extract stego.png
```

## Large text payload (Step 2)
```bash
./stego embed image.png stego.png secret.txt
./stego extract stego.png
```

## Metrics for images (Step 3)
```bash
./stego metrics image.png stego.png
# Goal: PSNR > 35 dB, SSIM > 0.95
```

## Adaptive LSB (Step 4)
```bash
./stego adaptive_embed image.png adaptive.png "hello adaptive"
./stego metrics image.png adaptive.png
```

## AES-256 encrypted image payload
```bash
./stego adaptive_encrypt_embed image.png stego_enc.png "HELLO_AES" mypassword123
./stego adaptive_decrypt_extract stego_enc.png mypassword123
```

## Video workflows
- Text-in-video:
```bash
./stego video_embed_text cat_laughing.mp4 stego_cat.avi "hi i am text"
./stego video_extract_text stego_cat.avi
```
- File-in-video:
```bash
./stego video_embed_file music_mjpg.avi stego_video.avi secret_small.mp4
./stego video_extract_file stego_video.avi extracted.mp4
```
- Encrypted video payloads:
```bash
./stego video_encrypt_embed_text cat_laughing.mp4 stego_cat_enc.avi "secret_msg" mypass
./stego video_encrypt_extract_text stego_cat_enc.avi mypass
./stego video_encrypt_embed_file cat_laughing.mp4 stego_cat_file_enc.avi secret_small.mp4 mypass
./stego video_encrypt_extract_file stego_cat_file_enc.avi mypass extracted_enc.mp4
```
- Selective-frame file-in-video (static-frame masking):
```bash
./stego video_embed_file_selective cat_laughing.avi stego_sel_video.avi secret_small.mp4
./stego video_extract_file_selective stego_video_sel.avi extracted_sel_fix.mp4
```

## Video metrics (PSNR/SSIM/VMAF/FPS)
```bash
./stego video_metrics cat_laughing.mp4 stego_cat_sel.avi --vmaf
```
Notes:
- If FFmpeg lacks `libvmaf` you will see “Filter not found”; the tool falls back to the external `vmaf` binary if present.
- Output includes frames used, processing FPS, PSNR/SSIM, sync error, and VMAF when available.

## GUI prerequisite (28/11)
```bash
sudo apt-get install python3-tk
```

## OUTPUT 
CANNOT DECODE
<img width="1232" height="819" alt="image" src="https://github.com/user-attachments/assets/f6987b0d-c6a7-4ed3-b888-90662da213c4" />

DECODE /
<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/632a3c55-591b-41e8-91d9-2918d1488e67" />



