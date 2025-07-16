#include <iostream>
#include <fstream>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/sha.h>

std::string hexstr(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

std::string hash_password(const std::string& password, const std::string& salt) {
    std::string salted = password + salt;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)salted.c_str(), salted.size(), digest);
    return hexstr(digest, SHA256_DIGEST_LENGTH);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <username> <password>\n";
        return 1;
    }
    std::string username = argv[1];
    std::string password = argv[2];
    unsigned char salt_bytes[16];
    RAND_bytes(salt_bytes, 16);
    std::string salt = hexstr(salt_bytes, 16);
    unsigned char kdf_salt_bytes[16];
    RAND_bytes(kdf_salt_bytes, 16);
    std::string kdf_salt = hexstr(kdf_salt_bytes, 16);
    std::string password_hash = hash_password(password, salt);
    std::string first_login_flag = "1";

    std::ofstream f("users.txt", std::ios::app);
    f << username << ":" << salt << ":" << password_hash << ":" << first_login_flag << ":" << kdf_salt << "\n";
    return 0;
} 