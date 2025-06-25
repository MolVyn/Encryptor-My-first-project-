#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
namespace fs = std::filesystem;

// Анимация прогресса
void ShowProgress(int percent, const std::string& operation) {
    std::cout << "\r[" << operation << "] [";
    for (int i = 0; i < 50; i++) {
        if (i < percent / 2) std::cout << "■";
        else std::cout << " ";
    }
    std::cout << "] " << percent << "%";
    std::cout.flush();
}

// Генерация ключа
void GenerateKey(const std::string& password, SecByteBlock& key, SecByteBlock& iv) {
    SecByteBlock salt(AES::BLOCKSIZE);
    AutoSeededRandomPool prng;
    prng.GenerateBlock(salt, salt.size());

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(
        key, key.size(),
        0x00,
        reinterpret_cast<const byte*>(password.data()), password.size(),
        salt, salt.size(),
        100000
    );
    prng.GenerateBlock(iv, iv.size());
}

// Чтение файла
std::string ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "";
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Запись файла
void WriteFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(data.data(), data.size());
}

// Шифрование файла
bool EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password1, const std::string& password2) {
    if (!fs::exists(inputFile)) {
        std::cerr << "✖ Ошибка: файл \"" << inputFile << "\" не существует!\n";
        return false;
    }

    try {
        std::cout << "\n▬▬▬▬▬▬▬▬ НАЧАЛО ШИФРОВАНИЯ ▬▬▬▬▬▬▬▬\n";

        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);

        std::string fullPassword = password1 + password2;
        GenerateKey(fullPassword, key, iv);

        std::string plaintext = ReadFile(inputFile);
        if (plaintext.empty()) {
            std::cerr << "✖ Ошибка чтения файла или файл пустой!\n";
            return false;
        }

        std::string ciphertext;
        CBC_Mode<AES>::Encryption encryptor(key, key.size(), iv);
        StringSource ss(
            plaintext, true,
            new StreamTransformationFilter(
                encryptor,
                new StringSink(ciphertext),
                BlockPaddingSchemeDef::PKCS_PADDING
            )
        );

        ciphertext.insert(0, reinterpret_cast<const char*>(iv.data()), iv.size());
        WriteFile(outputFile, ciphertext);

        for (int i = 0; i <= 100; i++) {
            ShowProgress(i, "ШИФРОВАНИЕ");
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        std::cout << "\n✔ Успешно зашифровано: " << outputFile << "\n";
        std::cout << "🔐 Ключ (HEX): ";
        StringSource(key.data(), key.size(), true, new HexEncoder(new FileSink(std::cout)));
        std::cout << "\n🔐 IV (HEX): ";
        StringSource(iv.data(), iv.size(), true, new HexEncoder(new FileSink(std::cout)));
        std::cout << "\n▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n";
        return true;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "\n✖ Крипто-ошибка: " << e.what() << "\n";
        return false;
    }
}

// Дешифрование файла
bool DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password1, const std::string& password2, const std::string& keyHex, const std::string& ivHex) {
    if (!fs::exists(inputFile)) {
        std::cerr << "✖ Ошибка: файл \"" << inputFile << "\" не существует!\n";
        return false;
    }

    try {
        std::cout << "\n▬▬▬▬▬▬▬▬ НАЧАЛО РАСШИФРОВКИ ▬▬▬▬▬▬▬▬\n";

        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);

        StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));
        StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

        std::string fullPassword = password1 + password2;

        std::string ciphertext = ReadFile(inputFile);
        if (ciphertext.size() <= AES::BLOCKSIZE) {
            std::cerr << "✖ Ошибка: недостаточно данных или повреждённый файл!\n";
            return false;
        }

        std::string encryptedData = ciphertext.substr(iv.size());
        std::string plaintext;

        CBC_Mode<AES>::Decryption decryptor(key, key.size(), iv);
        StringSource ss(
            encryptedData, true,
            new StreamTransformationFilter(
                decryptor,
                new StringSink(plaintext),
                BlockPaddingSchemeDef::PKCS_PADDING
            )
        );

        WriteFile(outputFile, plaintext);

        for (int i = 0; i <= 100; i++) {
            ShowProgress(i, "РАСШИФРОВКА");
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        std::cout << "\n✔ Успешно расшифровано: " << outputFile << "\n";
        std::cout << "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n";
        return true;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "\n✖ Ошибка расшифровки: возможно, один из паролей неверен или ключи не совпадают!\n";
        std::cerr << "Крипто-ошибка: " << e.what() << "\n";
        return false;
    }
}

int main() {
    std::cout << R"(
██████╗ ██████╗ ███████╗██╗   ██╗██████╗ ██╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██║   ██║██╔══██╗██║██╔════╝██╔══██╗
██████╔╝██████╔╝█████╗  ██║   ██║██████╔╝██║█████╗  ██████╔╝
██╔═══╝ ██╔═══╝ ██╔══╝  ██║   ██║██╔═══╝ ██║██╔══╝  ██╔══██╗
██║     ██║     ███████╗╚██████╔╝██║     ██║███████╗██║  ██║
╚═╝     ╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
    )" << '\n';

    int choice;
    do {
        std::cout << "\n1. 🔐 Зашифровать файл\n2. 🔓 Расшифровать файл\n3. ❌ Выход\n> ";
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 1) {
            std::string inputFile, outputFile, pass1, pass2;
            std::cout << "Введите путь к файлу для шифрования: ";
            std::getline(std::cin, inputFile);
            std::cout << "Введите путь для сохранения зашифрованного файла: ";
            std::getline(std::cin, outputFile);
            std::cout << "Введите ПЕРВЫЙ пароль: ";
            std::getline(std::cin, pass1);
            std::cout << "Введите ВТОРОЙ пароль: ";
            std::getline(std::cin, pass2);

            std::cout << "⚠️ ВАЖНО: сохраните оба пароля, без них расшифровка будет невозможна!\n";
            EncryptFile(inputFile, outputFile, pass1, pass2);
        }
        else if (choice == 2) {
            std::string inputFile, outputFile, pass1, pass2, keyHex, ivHex;
            std::cout << "Введите путь к зашифрованному файлу: ";
            std::getline(std::cin, inputFile);
            std::cout << "Введите путь для сохранения расшифрованного файла: ";
            std::getline(std::cin, outputFile);
            std::cout << "Введите ПЕРВЫЙ пароль: ";
            std::getline(std::cin, pass1);
            std::cout << "Введите ВТОРОЙ пароль: ";
            std::getline(std::cin, pass2);
            std::cout << "Введите КЛЮЧ (HEX): ";
            std::getline(std::cin, keyHex);
            std::cout << "Введите IV (HEX): ";
            std::getline(std::cin, ivHex);

            DecryptFile(inputFile, outputFile, pass1, pass2, keyHex, ivHex);
        }
    } while (choice != 3);

    std::cout << "\nДо свидания!\n";
    return 0;
}

