#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;
    std::string command;

    if (desc_.options().empty()) {
        desc_.add_options()("help,h", boost::program_options::value<bool>(&showHelp_)->implicit_value(true), "Showhelp"); 
        desc_.add_options()("input,i", boost::program_options::value<std::string>(&inputFile_), "Input file");
        desc_.add_options()("output,o", boost::program_options::value<std::string>(&outputFile_), "Output file");
        desc_.add_options()("password,p", boost::program_options::value<std::string>(&password_), "Password");
        desc_.add_options()("command,c", boost::program_options::value<std::string>(&command), "Command: encrypt, decrypt, checksum");
    }

    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);
    } catch (const po::error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cerr << desc_ << std::endl;
        throw;
    }

    if (showHelp_) {
        std::cout << desc_ << std::endl;
    } else { // command
        if (!vm.count("command")) {
            throw std::runtime_error("Command is required. Use --help for usage.");
        }

        auto it = commandMapping_.find(command);
        if (it == commandMapping_.end()) {
            throw std::invalid_argument("Unknown command: " + std::string(command));
        }
        
        command_ = it->second;

        if (!vm.count("input")) {
            throw std::runtime_error("Input file is required for all commands.");
        }

        if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
            if (!vm.count("output")) {
                throw std::runtime_error("Output file is required for encrypt/decrypt.");
            }

            if (!vm.count("password")) {
                throw std::runtime_error("Password is required for encrypt/decrypt.");
            }
        }
    }
}

}  // namespace CryptoGuard
