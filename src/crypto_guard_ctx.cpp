#include "crypto_guard_ctx.h"
#include <cstddef>
#include <memory>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <array>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    Impl() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    ~Impl() {
        EVP_cleanup();
        ERR_free_strings(); 
    }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good()) {
            throw std::runtime_error("Input stream not good");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Output stream not good");
        }

        auto params = CreateChiperParamsFromPassword(password);

        auto deleter = [](EVP_CIPHER_CTX* p) { EVP_CIPHER_CTX_free(p); };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(deleter)> ctx(EVP_CIPHER_CTX_new());

        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }

        CheckOpenSslError(EVP_CipherInit_ex2(ctx.get(), params.cipher, nullptr, nullptr, 1, nullptr), "Failed to initialize cipher");

        if (EVP_CIPHER_CTX_get_key_length(ctx.get()) != params.KEY_SIZE) {
            throw std::runtime_error("Invalid key length");
        }
        
        if (EVP_CIPHER_CTX_get_iv_length(ctx.get()) != params.IV_SIZE) {
            throw std::runtime_error("Invalid IV length");
        }

        CheckOpenSslError(EVP_CipherInit_ex2(ctx.get(), nullptr, params.key.data(), params.iv.data(), 1, nullptr), "Failed to set key and IV");

        std::vector<unsigned char> inBuf(1024);  
        std::vector<unsigned char> outBuf(inBuf.size() + EVP_MAX_BLOCK_LENGTH);  
        
        int inLen = 0;
        int outLen = 0;
        
        while (inStream.good() && !inStream.eof()) {
            inStream.read(reinterpret_cast<char*>(inBuf.data()), inBuf.size());
            inLen = inStream.gcount();
            
            if (inLen <= 0) {
                break;
            }
            
            CheckOpenSslError(EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen), "EVP_CipherUpdate failed");
            
            if (!outStream.good()) {
                throw std::runtime_error("Output stream not good");
            }
            
            outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
            
            if (!outStream.good()) {
                throw std::runtime_error("Failed to write encrypted data to output stream");
            }
            
            if (inStream.bad()) {
                throw std::runtime_error("Input stream in bad state");
            }
        }

        CheckOpenSslError(EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen), "Encryption failed");
        
        if (outLen > 0) {
            if (!outStream.good()) {
                throw std::runtime_error("Output stream not good");
            }
            
            outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
            
            if (!outStream.good()) {
                throw std::runtime_error("Failed to write final encrypted block to output stream");
            }
        }
        
        outStream.flush();
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good()) {
            throw std::runtime_error("Input stream not good");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Output stream not good");
        }

        auto params = CreateChiperParamsFromPassword(password);
        
        auto deleter = [](EVP_CIPHER_CTX* p) { EVP_CIPHER_CTX_free(p); };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(deleter)> ctx(EVP_CIPHER_CTX_new());

        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }

        CheckOpenSslError(EVP_DecryptInit_ex2(ctx.get(), params.cipher, params.key.data(), params.iv.data(), nullptr), "Failed to initialize decryption");

        std::vector<unsigned char> inBuf(1024);
        std::vector<unsigned char> outBuf(inBuf.size() + EVP_MAX_BLOCK_LENGTH);
        
        int inLen = 0;
        int outLen = 0;
        
        while (inStream.good() && !inStream.eof()) {
            inStream.read(reinterpret_cast<char*>(inBuf.data()), inBuf.size());
            inLen = inStream.gcount();
            
            if (inLen <= 0) {
                break;
            }

            CheckOpenSslError(EVP_DecryptUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen), "Decryption failed");
            
            if (!outStream.good()) {
                throw std::runtime_error("Output stream not good");
            }
            
            outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
            
            if (!outStream.good()) {
                throw std::runtime_error("Failed to write decrypted data to output stream");
            }
            
            if (inStream.bad()) {
                throw std::runtime_error("Input stream bad state");
            }
        }

        CheckOpenSslError(EVP_DecryptFinal_ex(ctx.get(), outBuf.data(), &outLen), "Decryption failed");
        
        if (outLen > 0) {
            if (!outStream.good()) {
                throw std::runtime_error("Output stream not good");
            }
            
            outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
            
            if (!outStream.good()) {
                throw std::runtime_error("Failed to write final decrypted block to output stream");
            }
        }
        
        outStream.flush();
    }

    std::string CalculateChecksum(std::iostream &inStream) { 
        if (!inStream.good()) {
            throw std::runtime_error("Input stream not good");
        }

        inStream.peek();
        if (inStream.eof()) {
            throw std::runtime_error("Input stream is empty");
        }

        const EVP_MD* md = EVP_sha256();
        if (md == nullptr) {
            throw std::runtime_error("Failed to get SHA-256 digest");
        }

        auto deleter = [](EVP_MD_CTX* ptr) { EVP_MD_CTX_free(ptr); 
        };
        
        std::unique_ptr<EVP_MD_CTX, decltype(deleter)> mdctx(EVP_MD_CTX_new());

        if (!mdctx) {
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }

        CheckOpenSslError(EVP_DigestInit_ex(mdctx.get(), md, nullptr), "Failed to initialize digest");

        std::vector<unsigned char> buffer(8192);
        
        while (inStream.good() && !inStream.eof()) {
            inStream.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            std::streamsize bytesRead = inStream.gcount();
            
            if (bytesRead > 0) {
                CheckOpenSslError(EVP_DigestUpdate(mdctx.get(), buffer.data(), bytesRead), "Failed to update digest");
            }
            
            if (inStream.bad()) {
                throw std::runtime_error("Input bad");
            }
        }

        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;

        CheckOpenSslError(EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len), "Failed to finalize digest");

        std::stringstream result;
        result << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < md_len; ++i) {
            result << std::setw(2) << static_cast<int>(md_value[i]);
        }

        return result.str();
    }

private:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    void CheckOpenSslError(int result, const std::string &operation) {
        if (result == 1) { 
            return;
        }
        
        unsigned long errCode = ERR_get_error();
        char errBuf[256];
        
        if (errCode != 0) {
            ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
            throw std::runtime_error(operation + ": " + errBuf);
        } else {
            throw std::runtime_error(operation + ": unknown error (result=" + std::to_string(result) + ")");
        }
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    return pImpl_->CalculateChecksum(inStream);
} 
// 
}  // namespace CryptoGuard
