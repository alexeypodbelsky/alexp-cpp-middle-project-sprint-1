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
    TestData test_data{{"./test_app", "-i", "input.txt", "-o", "encrypted.txt", "-p", "1234", "--command", "encrypt"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    po->Parse(test_data.toArgc(), test_data.toArgv());
    EXPECT_EQ(po->GetCommand(), COMMAND_TYPE::ENCRYPT);
}

// test2: ./test_app -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt
TEST(ProgramOptions, Test2) { 
    TestData test_data{{"./test_app", "-i", "encrypted.txt", "-o", "decrypted.txt", "-p", "1234", "--command", "decrypt"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    po->Parse(test_data.toArgc(), test_data.toArgv());
    EXPECT_EQ(po->GetCommand(), COMMAND_TYPE::DECRYPT); 
}

// test3: ./test_app -i input.txt --command checksum
TEST(ProgramOptions, Test3) { 
    TestData test_data{{"./test_app", "-i", "input.txt","--command", "checksum"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    po->Parse(test_data.toArgc(), test_data.toArgv());
    EXPECT_EQ(po->GetCommand(), COMMAND_TYPE::CHECKSUM);  
}

// test4 no command: ./test_app -i decrypted.txt
TEST(ProgramOptions, Test4) { 
    TestData test_data{{"./test_app", "-i", "decrypted.txt"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    EXPECT_THROW(po->Parse(test_data.toArgc(), test_data.toArgv()), std::runtime_error); 
}

// test5 incorrect command: ./test_app -i input.txt --command checksumMMM
TEST(ProgramOptions, Test5) { 
    TestData test_data{{"./test_app", "-i", "input.txt","--command", "checksumMMM"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    EXPECT_THROW(po->Parse(test_data.toArgc(), test_data.toArgv()), std::invalid_argument); 
 }

// test6 input file option check: ./test_app -i input.txt -o encrypted.txt -p  --command encrypt
TEST(ProgramOptions, Test6) { 
    TestData test_data{{"./test_app", "-i", "input.txt", "-o", "encrypted.txt", "-p", "--command", "encrypt"}};
    std::unique_ptr<CryptoGuard::ProgramOptions> po = std::make_unique<CryptoGuard::ProgramOptions>();
    EXPECT_THROW(po->Parse(test_data.toArgc(), test_data.toArgv()), std::runtime_error); 
 }
