#include "utility.h"
#include "crypto.h"
#include "constants.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <openssl/crypto.h>  
#include <openssl/rand.h>
#include <fstream> 
#include <sys/stat.h> 
using namespace std;

int main(int argc, char** argv) {
    // Interactive prompts for server, port, username
    string host, user, port_str;
    int port;
    cout << "Welcome to the Digital Signature Server (DSS) client!" << endl;
    cout << "Server address [127.0.0.1]: ";
    getline(cin, host);
    if (host.empty()) host = "127.0.0.1";
    cout << "Port [5252]: ";
    getline(cin, port_str);
    if (port_str.empty()) port = 5252;
    else port = atoi(port_str.c_str());
    cout << "Username: ";
    getline(cin, user);
    if (user.empty()) {
        cout << "Username is required." << endl;
        return 1;
    }

    // --- connect to server ---
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &srv.sin_addr);
    if (connect(fd, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        perror("connect");
        return 1;
    }

    // --- Diffie-Hellman handshake ---
    EVP_PKEY* mydh = generate_dh_keypair();

    // send our public key
    const DH* dh = EVP_PKEY_get0_DH(mydh);
    const BIGNUM* pubkey = nullptr;
    DH_get0_key(dh, &pubkey, nullptr);
    int publen = BN_num_bytes(pubkey);
    vector<unsigned char> pub(publen);
    BN_bn2bin(pubkey, pub.data());

    uint32_t netlen = htonl((uint32_t)publen);
    send_raw(fd, (unsigned char*)&netlen, sizeof(netlen));
    send_raw(fd, pub.data(), publen);

    // receive server public key
    uint32_t srvlen_n;
    recv_raw(fd, (unsigned char*)&srvlen_n, sizeof(srvlen_n));
    size_t srvlen = ntohl(srvlen_n);
    vector<unsigned char> srvpub(srvlen);
    recv_raw(fd, srvpub.data(), srvlen);

    // reconstruct peer public EVP_PKEY
    const DH* dh_params = EVP_PKEY_get0_DH(mydh);
    const BIGNUM *p = nullptr, *g = nullptr;
    DH_get0_pqg(dh_params, &p, nullptr, &g);
    DH* pdh = DH_new();
    DH_set0_pqg(pdh, BN_dup(p), nullptr, BN_dup(g));
    BIGNUM* pub_bn = BN_bin2bn(srvpub.data(), srvlen, nullptr);
    DH_set0_key(pdh, pub_bn, nullptr);

    EVP_PKEY* peer = EVP_PKEY_new();
    EVP_PKEY_assign_DH(peer, pdh);

    // derive shared secret 
    unsigned char* secret = nullptr;
    size_t secret_len = 0;
    derive_dh_shared_secret(peer, mydh, secret, secret_len);
    unsigned char session_key[AES_KEY_SIZE];
    memcpy(session_key, secret, AES_KEY_SIZE);
    free(secret);
    EVP_PKEY_free(mydh);
    EVP_PKEY_free(peer);

    // --- Server Authentication (Challenge/Response) ---
    // Load server public key
    EVP_PKEY* server_pub = load_public_pem("keys/server_pub.pem");
    if (!server_pub) {
        cerr << "Failed to load server public key!" << endl;
        close(fd);
        return 1;
    }
    // Generate random challenge
    unsigned char challenge[32];
    RAND_bytes(challenge, sizeof(challenge));
    string challenge_str((char*)challenge, sizeof(challenge));
    network_message chal_msg{0, CMD_SERVER_AUTH, (uint16_t)challenge_str.size(), challenge_str};
    send_auth_and_encrypted_message(fd, chal_msg, session_key);
    // Receive signature
    network_message sig_msg;
    if (!receive_auth_and_encrypted_message(fd, sig_msg, session_key) || sig_msg.command != CMD_SERVER_AUTH) {
        cerr << "Failed to receive server signature!" << endl;
        EVP_PKEY_free(server_pub);
        close(fd);
        return 1;
    }
    // Verify signature
    const string& sig = sig_msg.content;
    bool ok = rsa_verify(server_pub, challenge, sizeof(challenge), (const unsigned char*)sig.data(), sig.size());
    EVP_PKEY_free(server_pub);
    if (!ok) {
        cerr << "Server authentication failed!" << endl;
        close(fd);
        return 1;
    }

    // --- Authentication over AES-GCM ---
    cout << "Password: ";
    string pass;
    getline(cin, pass);
    if (pass.empty()) getline(cin, pass);

    string up = user + "|" + pass;
    network_message auth_msg{0, 0, (uint16_t)up.size(), up};
    send_auth_and_encrypted_message(fd, auth_msg, session_key);

    network_message resp;
    if (!receive_auth_and_encrypted_message(fd, resp, session_key)) {
        cerr << "Authentication failed" << endl;
        close(fd);
        return 1;
    }
    if (resp.command == CMD_CHANGE_PASSWORD) {
        cout << "First login detected. You must change your password before continuing." << endl;
        cout << "Please enter a new password: ";
        string newpass;
        getline(cin, newpass);
        if (newpass.empty()) getline(cin, newpass);
        network_message change_msg{0, CMD_CHANGE_PASSWORD, (uint16_t)newpass.size(), newpass};
        send_auth_and_encrypted_message(fd, change_msg, session_key);
        if (!receive_auth_and_encrypted_message(fd, resp, session_key) || resp.command != CMD_OK) {
            cerr << "Password change failed" << endl;
            close(fd);
            return 1;
        }
        cout << "Password changed successfully. You are now logged in." << endl;
    } else if (resp.command != CMD_OK) {
        cerr << "Authentication failed" << endl;
        close(fd);
        return 1;
    }

    // Print help menu
    auto print_help = []() {
        cout << "\nWelcome to the Digital Signature Server (DSS) client!" << endl;
        cout << "Available commands:" << endl;
        cout << "  create           - Create your key pair" << endl;
        cout << "  sign <file>      - Digitally sign a document (file contents)" << endl;
        cout << "  getpub <user>    - Get a user's public key" << endl;
        cout << "  delete           - Delete your key pair" << endl;
        cout << "  help             - Show this help menu" << endl;
        cout << "  exit             - Quit the application" << endl;
    };

    print_help();

    // --- Interactive command loop ---
    while (true) {
        cout << "cmd> ";
        string line;
        if (!getline(cin, line) || line.empty()) break;

        istringstream is(line);
        string cmd;
        is >> cmd;
        network_message req;
        static uint16_t nonce = 1;
        req.nonce = nonce++;

        if (cmd == "help") {
            print_help();
            continue;
        } else if (cmd == "exit") {
            cout << "Goodbye!" << endl;
            break;
        } else if (cmd == "create") {
            req.command = CREATEKEYS_COMMAND;
            req.content_length = (uint16_t)user.size();
            req.content = user;
        } else if (cmd == "sign") {
            string doc;
            is >> doc;
            if (doc.empty()) {
                cout << "ERROR: sign command requires a document argument" << endl;
                continue;
            }
       
            struct stat s;
            if (stat(doc.c_str(), &s) == 0 && S_ISDIR(s.st_mode)) {
                cout << "ERROR: '" << doc << "' is a directory, not a file." << endl;
                continue;
            }
          
            ifstream infile(doc);
            string content;
            if (infile.is_open()) {
                
                content.assign((istreambuf_iterator<char>(infile)), istreambuf_iterator<char>());
                infile.close();
            } else {
             
                content = doc;
            }
            req.command = SIGN_COMMAND;
            req.content = user + "|" + content;
            req.content_length = (uint16_t)req.content.size();
        } else if (cmd == "getpub") {
            string target;
            is >> target;
            if (target.empty()) {
                cout << "ERROR: getpub command requires a username argument" << endl;
                continue;
            }
            req.command = GETPUB_COMMAND;
            req.content_length = (uint16_t)target.size();
            req.content = target;
        } else if (cmd == "delete") {
            req.command = DELETE_COMMAND;
            req.content_length = (uint16_t)user.size();
            req.content = user;
        } else {
            cout << "Unknown command. Type 'help' for a list of commands." << endl;
            continue;
        }

        send_auth_and_encrypted_message(fd, req, session_key);
        receive_auth_and_encrypted_message(fd, resp, session_key);
        if (resp.command == CMD_OK) {
            cout << "OK";
            if (resp.content_length) cout << ": " << resp.content;
            cout << endl;
        } else {
            if (req.command == GETPUB_COMMAND) {
                cout << "No such user or public key found." << endl;
            } else {
                cout << "ERROR";
                if (resp.content_length) cout << ": " << resp.content;
                cout << endl;
            }
        }
    }

    close(fd);
    return 0;
}