#include "../include/cmd_options.h"
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>

using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

struct TestData {
    std::vector<const char *> args;

    int toArgc() const { return static_cast<int>(args.size()); }
    char **toArgv() { return const_cast<char **>(args.data()); }

    void printTestData() const {
        for (int i = 0; i < toArgc(); i++) {
            std::cout << "i = " << i << " arg = " << args[i] << std::endl;
        }
    }
};

// test1: ./test_app -i input.txt -o encrypted.txt -p 1234 --command encrypt
TEST(ProgramOptions, Test1) {
    TestData testData{{"./test_app", "-i", "input.txt", "-o", "encrypted.txt", "-p", "1234", "--command", "encrypt"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    po->Parse(testData.toArgc(), testData.toArgv());
    EXPECT_EQ(po->GetCommand(), COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(po->GetInputFile(), "input.txt");
    EXPECT_EQ(po->GetOutputFile(), "encrypted.txt");
    EXPECT_EQ(po->GetPassword(), "1234");
}

// test2: ./test_app -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt
TEST(ProgramOptions, Test2) { 
    TestData testData{{"./test_app", "-i", "encrypted.txt", "-o", "decrypted.txt", "-p", "1234", "--command", "decrypt"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    po->Parse(testData.toArgc(), testData.toArgv());
    EXPECT_EQ(po->GetCommand(), COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(po->GetInputFile(), "encrypted.txt");
    EXPECT_EQ(po->GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(po->GetPassword(), "1234"); 
}

// test3: ./test_app -i input.txt --command checksum
TEST(ProgramOptions, Test3) { 
    TestData testData{{"./test_app", "-i", "input.txt","--command", "checksum"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    po->Parse(testData.toArgc(), testData.toArgv());
    EXPECT_EQ(po->GetCommand(), COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(po->GetInputFile(), "input.txt");
}

// test4 no command: ./test_app -i decrypted.txt
TEST(ProgramOptions, Test4) { 
    TestData testData{{"./test_app", "-i", "decrypted.txt"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    EXPECT_THROW(po->Parse(testData.toArgc(), testData.toArgv()), std::runtime_error); 
}

// test5 incorrect command: ./test_app -i input.txt --command checksumMMM
TEST(ProgramOptions, Test5) { 
    TestData testData{{"./test_app", "-i", "input.txt","--command", "checksumMMM"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    EXPECT_THROW(po->Parse(testData.toArgc(), testData.toArgv()), std::invalid_argument); 
 }

// test6 input file option check: ./test_app -i input.txt -o encrypted.txt -p  --command encrypt
TEST(ProgramOptions, Test6) { 
    TestData testData{{"./test_app", "-i", "input.txt", "-o", "encrypted.txt", "-p", "--command", "encrypt"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    EXPECT_THROW(po->Parse(testData.toArgc(), testData.toArgv()), std::runtime_error); 
 }
