#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <assert.h>
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

std::fstream OpenFile(const std::string& filename, std::ios::openmode mode) {
    std::fstream file(filename, mode);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    return file;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        
        switch (options.GetCommand()) {
        case COMMAND_TYPE::NOCOMMAND:
            break;
            
        case COMMAND_TYPE::ENCRYPT: 
        {
            auto inFile = OpenFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            auto outFile = OpenFile(options.GetOutputFile(), std::ios::out | std::ios::binary);
            cryptoCtx.EncryptFile(inFile, outFile, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: 
        {
            auto inFile = OpenFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            auto outFile = OpenFile(options.GetOutputFile(), std::ios::out | std::ios::binary);
            cryptoCtx.DecryptFile(inFile, outFile, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM:
        {
            auto inFile = OpenFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            std::string checksum = cryptoCtx.CalculateChecksum(inFile);
            std::print("Checksum (SHA-256) of {}: {}\n", options.GetInputFile(), checksum);
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}