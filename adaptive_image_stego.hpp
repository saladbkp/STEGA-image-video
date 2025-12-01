#ifndef ADAPTIVE_IMAGE_STEGO_HPP
#define ADAPTIVE_IMAGE_STEGO_HPP

#include <string>

namespace imgstego {

    bool embedTextAdaptive(const std::string& coverImagePath,
                           const std::string& stegoImagePath,
                           const std::string& message);

    bool extractTextAdaptive(const std::string& stegoImagePath,
                             std::string& outMessage);

    bool embedTextAdaptiveEncrypted(const std::string& coverImagePath,
                                    const std::string& stegoImagePath,
                                    const std::string& plaintext,
                                    const std::string& password);

    bool extractTextAdaptiveEncrypted(const std::string& stegoImagePath,
                                      const std::string& password,
                                      std::string& outPlaintext);
}

#endif
