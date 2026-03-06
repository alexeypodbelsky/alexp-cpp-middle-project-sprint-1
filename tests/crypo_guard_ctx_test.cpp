#include <gtest/gtest.h>
#include "crypto_guard_ctx.h"

// EncryptFile. Bad input stream
TEST(CryptoGuardCtx, Test1) { 
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream badStream;
    std::stringstream outStream;
    std::string password = "1234";
    
    badStream.setstate(std::ios::badbit);
    
    ASSERT_THROW(ctx.EncryptFile(badStream, outStream, password), std::runtime_error);
 }

// EncryptFile. Bad output stream
TEST(CryptoGuardCtx, Test2) { 
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream;
    std::stringstream badOutStream;
    std::string data = "Test data";
    std::string password = "test_password";
    
    inStream << data;
    inStream.seekg(0);
    badOutStream.setstate(std::ios::badbit);
    
    ASSERT_THROW(ctx.EncryptFile(inStream, badOutStream, password), std::runtime_error);
 }

// EncryptFile. Empty password
TEST(CryptoGuardCtx, Test3) { 
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream("test");
    std::stringstream outStream;
    std::string password = "";
    
    EXPECT_NO_THROW(ctx.EncryptFile(inStream, outStream, password));
 }

 // DecryptFile. Encrypt-Decrypt. 
TEST(CryptoGuardCtx, Test4) { 
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream;
    std::stringstream encryptedStream;
    std::stringstream decryptedStream;
    
    std::string originalData = "Test data";
    std::string password = "test_password";
    
    inStream << originalData;
    inStream.seekg(0);
    
    ctx.EncryptFile(inStream, encryptedStream, password);
    std::string encrypted_str = encryptedStream.str();
    
    EXPECT_NE(encrypted_str, originalData);
    EXPECT_FALSE(encrypted_str.empty());
    
    std::stringstream decryptInStream(encrypted_str);
    ctx.DecryptFile(decryptInStream, decryptedStream, password);
    
    std::string decryptedData = decryptedStream.str();
    EXPECT_EQ(decryptedData, originalData);
 }

 // DecryptFile. wrong password
 TEST(CryptoGuardCtx, Test5) { 
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream;
    std::stringstream encryptedStream;
    
    std::string originalData = "Test data";
    std::string correctPassword = "correct_password";
    std::string wrongPassword = "wrong_password";
    
    inStream << originalData;
    inStream.seekg(0);
    ctx.EncryptFile(inStream, encryptedStream, correctPassword);
    std::string encrypted_str = encryptedStream.str();
    
    std::stringstream decryptInStream(encrypted_str);
    std::stringstream decryptedStream;
    
    ASSERT_THROW(ctx.DecryptFile(decryptInStream, decryptedStream, wrongPassword), std::runtime_error);
 }

 // DecryptFile. corrupted data
TEST(CryptoGuardCtx, Test6) { 
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream;
    std::stringstream encryptedStream;
    
    std::string originalData = "Test data";
    std::string password = "test_password";
    
    inStream << originalData;
    inStream.seekg(0);
    ctx.EncryptFile(inStream, encryptedStream, password);
    std::string encrypted_str = encryptedStream.str();
    
    if (!encrypted_str.empty()) {
        encrypted_str[encrypted_str.size() / 2] ^= 0xFF;
    }
    
    std::stringstream decryptInStream(encrypted_str);
    std::stringstream decryptedStream;
    
    ASSERT_THROW(ctx.DecryptFile(decryptInStream, decryptedStream, password), 
                 std::runtime_error);
 }

 // CalculateChecksum. Consitent
TEST(CryptoGuardCtx, Test7) { 
    CryptoGuard::CryptoGuardCtx ctx;
    std::string data = "Consistency test data";
    
    std::stringstream inStream1(data);
    std::string checksum1 = ctx.CalculateChecksum(inStream1);
    
    std::stringstream inStream2(data);
    std::string checksum2 = ctx.CalculateChecksum(inStream2);
    
    EXPECT_EQ(checksum1, checksum2);
    EXPECT_EQ(checksum1.length(), 64);
    EXPECT_EQ(checksum2.length(), 64);
 }

  // CalculateChecksum. Integrity
TEST(CryptoGuardCtx, Test8) { 
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream;
    std::stringstream encryptedStream;
    std::stringstream decryptedStream;
    std::stringstream checksumStream1;
    std::stringstream checksumStream2;
    
    std::string originalData = "Test data for integrity";
    std::string password = "test_password";
    
    inStream << originalData;
    inStream.seekg(0);
    
    checksumStream1 << originalData;
    checksumStream1.seekg(0);
    std::string originalChecksum = ctx.CalculateChecksum(checksumStream1);
    
    inStream.clear();
    inStream.seekg(0);
    ctx.EncryptFile(inStream, encryptedStream, password);
    std::string encrypted_str = encryptedStream.str();
    
    EXPECT_NE(encrypted_str, originalData);
    EXPECT_FALSE(encrypted_str.empty());
    
    std::stringstream decryptInStream(encrypted_str);
    ctx.DecryptFile(decryptInStream, decryptedStream, password);
    
    std::string decryptedData = decryptedStream.str();
    EXPECT_EQ(decryptedData, originalData);
    
    checksumStream2 << decryptedData;
    checksumStream2.seekg(0);
    std::string decryptedChecksum = ctx.CalculateChecksum(checksumStream2);
    
    EXPECT_EQ(originalChecksum, decryptedChecksum);
 }
