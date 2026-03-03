#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // - Реализуйте конструктор, который настроит парсер командной строки с помощью boost::program_options для следующих
    // опций:
    // help — список доступных опций;
    // command — команда encrypt, decrypt или checksum;
    // input — путь до входного файла;
    // output — путь до файла, в котором будет сохранён результат;
    // password — пароль для шифрования и дешифрования.
    // - Добавьте обработку перечисленных опций с соответствующими параметрами (например, входные и выходные
    // данные для шифрования файла) и их проверку.
    // - Реализуйте маппинг строковых команд на enum COMMAND_TYPE.
    // - Добавьте вызов метода Parse(), который в случае ошибки будет выводить сообщение об ошибке, а при выборе help —
    // список доступных опций.
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    // desc_.add_options()("help,h", boost::program_options::value<bool>(&showHelp_)->implicit_value(true), "Show
    // help"); desc_.add_options()("input,i", boost::program_options::value<std::string>(&inputFile_), "Input file");
    // desc_.add_options()("output,o", boost::program_options::value<std::string>(&outputFile_), "Output file");
    // desc_.add_options()("password,p", boost::program_options::value<std::string>(&password_), "Password");

    namespace po = boost::program_options;
    std::string command;
    std::string input_file;
    std::string output_file;
    std::string password;

    // Описание опций
    po::options_description desc("Использование: программа [ОПЦИИ]");

    desc.add_options()
    ("help,h", "Показать справку")
    ("command,c", po::value<std::string>(&command), 
        "Команда: encrypt/decrypt/checksum")
    ("input,i", po::value<std::string>(&input_file), 
        "Входной файл")
    ("output,o", po::value<std::string>(&output_file), 
        "Выходной файл")
    ("password,p", po::value<std::string>(&password), 
        "Пароль");

    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error &e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        std::cerr << desc << std::endl;
    }

    std::cout << "Команда: " << command << std::endl;
    std::cout << "Input: " << input_file << std::endl;
    std::cout << "Output: " << output_file << std::endl;
    std::cout << "pass: " << password << std::endl;
}

}  // namespace CryptoGuard
