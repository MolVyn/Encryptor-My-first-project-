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

void ShowProgress(int percent, const std::string& operation) {
    std::cout << "\r[" << operation << "] [";
    for (int i = 0; i < 50; i++) {
        if (i < percent / 2) std::cout << "■";
        else std::cout << " ";
    }
    std::cout << "] " << percent << "%";
    std::cout.flush();
}

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

std::string ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "";
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void WriteFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(data.data(), data.size());
}

bool EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password1, const std::string& password2) {
    if (!fs::exists(inputFile)) {
        std::cerr << "✖ Error: File \"" << inputFile << "\" does not exist!\n";
        return false;
    }

    try {
        std::cout << "\n▬▬▬▬▬▬▬▬ STARTING ENCRYPTION ▬▬▬▬▬▬▬▬\n";

        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);
        std::string fullPassword = password1 + password2;
        GenerateKey(fullPassword, key, iv);

        std::string plaintext = ReadFile(inputFile);
        if (plaintext.empty()) {
            std::cerr << "✖ Error: File read failed or file is empty!\n";
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
            ShowProgress(i, "ENCRYPTING");
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        std::cout << "\n✔ Successfully encrypted: " << outputFile << "\n";
        std::cout << "🔐 Key (HEX): ";
        StringSource(key.data(), key.size(), true, new HexEncoder(new FileSink(std::cout)));
        std::cout << "\n🔐 IV (HEX): ";
        StringSource(iv.data(), iv.size(), true, new HexEncoder(new FileSink(std::cout)));
        std::cout << "\n▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n";
        return true;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "\n✖ Crypto Error: " << e.what() << "\n";
        return false;
    }
}

bool DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password1, const std::string& password2, const std::string& keyHex, const std::string& ivHex) {
    if (!fs::exists(inputFile)) {
        std::cerr << "✖ Error: File \"" << inputFile << "\" does not exist!\n";
        return false;
    }

    try {
        std::cout << "\n▬▬▬▬▬▬▬▬ STARTING DECRYPTION ▬▬▬▬▬▬▬▬\n";

        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);

        StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));
        StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

        std::string fullPassword = password1 + password2;

        std::string ciphertext = ReadFile(inputFile);
        if (ciphertext.size() <= AES::BLOCKSIZE) {
            std::cerr << "✖ Error: Invalid or corrupted file!\n";
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
            ShowProgress(i, "DECRYPTING");
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }

        std::cout << "\n✔ Successfully decrypted: " << outputFile << "\n";
        std::cout << "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n";
        return true;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "\n✖ Decryption Error: Possibly wrong password or invalid key/IV.\n";
        std::cerr << "Crypto Exception: " << e.what() << "\n";
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
        std::cout << "\n1. 🔐 Encrypt File\n2. 🔓 Decrypt File\n3. ❌ Exit\n> ";
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 1) {
            std::string inputFile, outputFile, pass1, pass2;
            std::cout << "Enter input file path: ";
            std::getline(std::cin, inputFile);
            std::cout << "Enter output file path: ";
            std::getline(std::cin, outputFile);
            std::cout << "Enter FIRST password: ";
            std::getline(std::cin, pass1);
            std::cout << "Enter SECOND password: ";
            std::getline(std::cin, pass2);

            std::cout << "⚠️ WARNING: Save both passwords. Without them, decryption is impossible!\n";
            EncryptFile(inputFile, outputFile, pass1, pass2);
        }
        else if (choice == 2) {
            std::string inputFile, outputFile, pass1, pass2, keyHex, ivHex;
            std::cout << "Enter encrypted file path: ";
            std::getline(std::cin, inputFile);
            std::cout << "Enter output file path: ";
            std::getline(std::cin, outputFile);
            std::cout << "Enter FIRST password: ";
            std::getline(std::cin, pass1);
            std::cout << "Enter SECOND password: ";
            std::getline(std::cin, pass2);
            std::cout << "Enter KEY (HEX): ";
            std::getline(std::cin, keyHex);
            std::cout << "Enter IV (HEX): ";
            std::getline(std::cin, ivHex);

            DecryptFile(inputFile, outputFile, pass1, pass2, keyHex, ivHex);
        }
    } while (choice != 3);

    std::cout << "\nGoodbye!\n";
    return 0;
}
