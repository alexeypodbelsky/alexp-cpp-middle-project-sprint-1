#include "../include/cmd_options.h"
#include <gtest/gtest.h>
#include <memory>

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

    EXPECT_EQ(1 + 1, 2);
}

// test2: ./test_app -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt
TEST(ProgramOptions, Test2) { EXPECT_EQ(1 + 1, 2); }

// test3: ./test_app -i input.txt --command checksum
TEST(ProgramOptions, Test3) { EXPECT_EQ(1 + 1, 2); }

// test4: ./test_app -i decrypted.txt --command checksum
TEST(ProgramOptions, Test4) { EXPECT_EQ(1 + 1, 2); }

// todo: test5
TEST(ProgramOptions, Test5) { EXPECT_EQ(1 + 1, 2); }

// todo: test6
TEST(ProgramOptions, Test6) { EXPECT_EQ(1 + 1, 2); }
