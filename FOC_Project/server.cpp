// File: server.cpp
#include "server.h"
#include "crypto.h"
#include "constants.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>
#include <iomanip>

// —— Constructor: bind & listen —————————————————————————————————————
Server::Server(int p): port(p) {
  struct sockaddr_in addr{};
  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);
  if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind");
    exit(1);
  }
  if (listen(listen_fd, 10) < 0) {
    perror("listen");
    exit(1);
  }
  mkdir(KEY_DIR, 0700);
}

// —— Main event loop —————————————————————————————————————————————
void Server::start(){
  fd_set master, read_fds;
  FD_ZERO(&master); FD_ZERO(&read_fds);
  FD_SET(listen_fd, &master);
  int fdmax = listen_fd;

  while(true){
    read_fds = master;
    select(fdmax+1, &read_fds, NULL, NULL, NULL);
    for(int i=0; i <= fdmax; i++){
      if(!FD_ISSET(i, &read_fds)) continue;

      if(i == listen_fd){
        int newfd = accept(listen_fd, NULL, NULL);

        // —— Perform DH handshake immediately ——
        EVP_PKEY* mydh = generate_dh_keypair();
        const DH* dh = EVP_PKEY_get0_DH(mydh);
        const BIGNUM* pubkey = nullptr;
        DH_get0_key(dh, &pubkey, nullptr);
        size_t publen = BN_num_bytes(pubkey);
        unsigned char pubbuf[512];
        BN_bn2bin(pubkey, pubbuf);
        uint32_t netlen = htonl((uint32_t)publen);
        send_raw(newfd, (unsigned char*)&netlen, sizeof(netlen));
        send_raw(newfd, pubbuf, publen);

        uint32_t peerlen;
        recv_raw(newfd, (unsigned char*)&peerlen, 4);
        peerlen = ntohl(peerlen);
        unsigned char *peerbuf = (unsigned char*)malloc(peerlen);
        recv_raw(newfd, peerbuf, peerlen);
        const DH* dh_params = EVP_PKEY_get0_DH(mydh);
        const BIGNUM *p = nullptr, *g = nullptr;
        DH_get0_pqg(dh_params, &p, nullptr, &g);
        DH* pdh = DH_new();
        DH_set0_pqg(pdh, BN_dup(p), nullptr, BN_dup(g));
        BIGNUM* pub_bn = BN_bin2bn(peerbuf, peerlen, nullptr);
        DH_set0_key(pdh, pub_bn, nullptr);

        EVP_PKEY *peerkey = EVP_PKEY_new();
        EVP_PKEY_assign_DH(peerkey, pdh);
        free(peerbuf);

        // derive AES key
        unsigned char *secret; size_t seclen;
        derive_dh_shared_secret(peerkey, mydh, secret, seclen);
        memcpy(session_key, secret, AES_KEY_SIZE);
        free(secret);
        EVP_PKEY_free(mydh);
        EVP_PKEY_free(peerkey);

        authenticated[std::to_string(newfd)] = false;
        FD_SET(newfd, &master);
        if(newfd > fdmax) fdmax = newfd;
        network_message nm;
        if (!receive_auth_and_encrypted_message(newfd, nm, session_key)) {
          close(newfd); FD_CLR(newfd, &master);
          continue;
        }
        if (nm.command == CMD_SERVER_AUTH) {
          // Load server private key
          EVP_PKEY* server_priv = load_private_pem("keys/server_priv.pem", nullptr);
          if (!server_priv) {
            close(newfd); FD_CLR(newfd, &master);
            continue;
          }
          // Sign the challenge
          const string& challenge = nm.content;
          unsigned char* sig = nullptr;
          size_t siglen = 0;
          rsa_sign(server_priv, (const unsigned char*)challenge.data(), challenge.size(), sig, siglen);
          EVP_PKEY_free(server_priv);
          string sig_str((char*)sig, siglen);
          free(sig);
          network_message sig_msg{0, CMD_SERVER_AUTH, (uint16_t)sig_str.size(), sig_str};
          send_auth_and_encrypted_message(newfd, sig_msg, session_key);
        } else {
          close(newfd); FD_CLR(newfd, &master);
          continue;
        }

      } else {
        network_message nm;
        if(!receive_auth_and_encrypted_message(i, nm, session_key)){
          close(i); FD_CLR(i, &master);
          continue;
        }

        std::string client_id = std::to_string(i);
        if(!authenticated[client_id]){
          std::istringstream upiss(nm.content);
          std::string user, pass;
          std::getline(upiss, user, '|');
          std::getline(upiss, pass);
          std::ifstream f(USERS_FILE);
          std::string line;
          bool found = false, must_change = false;
          std::string salt, hash, first_login;
          while (std::getline(f, line)) {
            std::istringstream iss(line);
            std::string username, salt, hash, first_login, kdf_salt;
            if (std::getline(iss, username, ':') &&
                std::getline(iss, salt, ':') &&
                std::getline(iss, hash, ':') &&
                std::getline(iss, first_login, ':') &&
                std::getline(iss, kdf_salt)) {
              first_login.erase(first_login.find_last_not_of(" \r\n\t") + 1);
              if (username == user) {
                std::string salted = pass + salt;
                unsigned char digest[SHA256_DIGEST_LENGTH];
                SHA256((unsigned char*)salted.c_str(), salted.size(), digest);
                std::ostringstream oss;
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                  oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
                if (oss.str() == hash) {
                  found = true;
                  if (first_login == "1") must_change = true;
                  break;
                }
              }
            }
          }
          if (!found) {
            network_message resp{0, CMD_ERROR, 0, ""};
            send_auth_and_encrypted_message(i, resp, session_key);
            close(i); FD_CLR(i, &master);
            continue;
          }
          if (must_change) {
            network_message resp{0, CMD_CHANGE_PASSWORD, 0, ""};
            send_auth_and_encrypted_message(i, resp, session_key);
            network_message nm2;
            if (!receive_auth_and_encrypted_message(i, nm2, session_key)) {
              close(i); FD_CLR(i, &master);
              continue;
            }
            std::string newpass = nm2.content;
            update_password(user, newpass);
            network_message resp2{0, CMD_OK, 0, "Password changed"};
            send_auth_and_encrypted_message(i, resp2, session_key);
            authenticated[client_id] = true;
            user_passwords[client_id] = newpass;
          } else {
            authenticated[client_id] = true;
            user_passwords[client_id] = pass;
            network_message resp{0, CMD_OK, 0, ""};
            send_auth_and_encrypted_message(i, resp, session_key);
          }
        } else {
          switch(nm.command){
            case CREATEKEYS_COMMAND: handle_createkeys(i, nm); break;
            case SIGN_COMMAND:       handle_signdoc(i, nm);    break;
            case GETPUB_COMMAND:     handle_getpub(i, nm);     break;
            case DELETE_COMMAND:     handle_delete(i, nm);     break;
            default:{
              network_message r{nm.nonce, CMD_ERROR, 0, "BadCmd"};
              send_auth_and_encrypted_message(i, r, session_key);
            }
          }
        }
      }
    }
  }
}

// —— Helpers for user/password storage ——————————————————————————————
bool Server::load_users(){
  return true;
}
bool Server::verify_password(const std::string& u, const std::string& p) {
    std::ifstream f(USERS_FILE);
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string username, salt, hash, first_login;
        if (std::getline(iss, username, ':') &&
            std::getline(iss, salt, ':') &&
            std::getline(iss, hash, ':') &&
            std::getline(iss, first_login)) {
            if (username == u) {
                std::string salted = p + salt;
                unsigned char digest[SHA256_DIGEST_LENGTH];
                SHA256((unsigned char*)salted.c_str(), salted.size(), digest);
                std::ostringstream oss;
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
                if (oss.str() == hash) {
                    if (first_login == "1") {
                        return false; 
                    }
                    return true; 
                }
            }
        }
    }
    return false; 
}

bool Server::update_password(const std::string& u, const std::string& p) {
    std::ifstream f(USERS_FILE);
    std::vector<std::string> lines;
    std::string line;
    bool updated = false;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string username, salt, hash, first_login, kdf_salt;
        if (std::getline(iss, username, ':') &&
            std::getline(iss, salt, ':') &&
            std::getline(iss, hash, ':') &&
            std::getline(iss, first_login, ':') &&
            std::getline(iss, kdf_salt)) {
            if (username == u) {
                unsigned char new_salt_bytes[16];
                RAND_bytes(new_salt_bytes, 16);
                std::ostringstream saltoss;
                for (int i = 0; i < 16; ++i)
                    saltoss << std::hex << std::setw(2) << std::setfill('0') << (int)new_salt_bytes[i];
                std::string new_salt = saltoss.str();
                std::string salted = p + new_salt;
                unsigned char digest[SHA256_DIGEST_LENGTH];
                SHA256((unsigned char*)salted.c_str(), salted.size(), digest);
                std::ostringstream oss;
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
                lines.push_back(username + ":" + new_salt + ":" + oss.str() + ":0:" + kdf_salt);
                updated = true;
            } else {
                lines.push_back(line);
            }
        } else {
            lines.push_back(line);
        }
    }
    f.close();
    if (updated) {
        std::ofstream out(USERS_FILE);
        for (auto& l : lines) out << l << "\n";
    }
    return updated;
}

// —— Operation implementations —————————————————————————————————————
void Server::handle_createkeys(int fd, const network_message& nm){
  std::string user = nm.content;
  std::string client_id = std::to_string(fd);
  std::string priv_path = KEY_DIR + user + "_priv.pem.enc";
  std::string pub_path = KEY_DIR + user + "_pub.pem";
  if (std::ifstream(priv_path) && std::ifstream(pub_path)) {
    network_message r{nm.nonce, CMD_OK, 0, ""};
    send_auth_and_encrypted_message(fd, r, session_key);
    return;
  }
  EVP_PKEY* kp = generate_rsa_keypair();
 
  BIO* mem = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(mem, kp, NULL, NULL, 0, NULL, NULL);
  char* pem_data = nullptr;
  long pem_len = BIO_get_mem_data(mem, &pem_data);
  std::string priv_pem(pem_data, pem_len);
  BIO_free(mem);

  std::string password = user_passwords[client_id];
  unsigned char key[32], iv[16];
  bool kdf_ok = derive_user_key(user, password, key, iv);
  if (!kdf_ok) {
    network_message r{nm.nonce, CMD_ERROR, 0, "Key derivation failed"};
    send_auth_and_encrypted_message(fd, r, session_key);
    EVP_PKEY_free(kp);
    return;
  }
  std::string enc_pem;
  bool enc_ok = aes_encrypt_pem(priv_pem, key, iv, enc_pem);
  std::string outpath = KEY_DIR + user + "_priv.pem.enc";
  std::ofstream f(outpath, std::ios::binary);
  if (f.is_open()) {
    f.write(enc_pem.data(), enc_pem.size());
    f.close();
  } else {
    printf("[DEBUG] Failed to open %s for writing!\n", outpath.c_str());
  }

  write_public_pem(kp, KEY_DIR + user + "_pub.pem");
  EVP_PKEY_free(kp);
  network_message r{nm.nonce, CMD_OK, 0, ""};
  send_auth_and_encrypted_message(fd, r, session_key);
}

void Server::handle_signdoc(int fd, const network_message& nm){
  // Parse user and document 
  size_t sep = nm.content.find('|');
  if (sep == std::string::npos) {
    network_message r{nm.nonce, CMD_ERROR, 0, "Malformed sign request"};
    send_auth_and_encrypted_message(fd, r, session_key);
    return;
  }
  std::string user = nm.content.substr(0, sep);
  std::string b64doc = nm.content.substr(sep + 1);
  if (b64doc.empty()) {
    network_message r{nm.nonce, CMD_ERROR, 0, "Missing document to sign"};
    send_auth_and_encrypted_message(fd, r, session_key);
    return;
  }
  std::string client_id = std::to_string(fd);
  std::string password = user_passwords[client_id];
  // Decrypt private key
  std::ifstream f(KEY_DIR + user + "_priv.pem.enc", std::ios::binary);
  std::string enc_pem((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  f.close();
  if (enc_pem.size() < 16) {
    std::string errmsg = "No key detected, please create";
    network_message r{nm.nonce, CMD_ERROR, (uint16_t)errmsg.size(), errmsg};
    send_auth_and_encrypted_message(fd, r, session_key);
    return;
  }
  unsigned char key[32], iv[16];
  bool kdf_ok = derive_user_key(user, password, key, iv);
  if (!kdf_ok) {
    network_message r{nm.nonce, CMD_ERROR, 0, "Key derivation failed"};
    send_auth_and_encrypted_message(fd, r, session_key);
    return;
  }
  std::string priv_pem;
  aes_decrypt_pem(enc_pem.substr(16), key, (const unsigned char*)enc_pem.data(), priv_pem);
  BIO* mem = BIO_new_mem_buf(priv_pem.data(), priv_pem.size());
  EVP_PKEY* pr = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
  BIO_free(mem);
  if (!pr) {
    network_message r{nm.nonce, CMD_ERROR, 0, "Failed to load private key"};
    send_auth_and_encrypted_message(fd, r, session_key);
    return;
  }
  unsigned char *sig; size_t siglen;
  rsa_sign(pr, (unsigned char*)b64doc.data(), b64doc.size(), sig, siglen);
  EVP_PKEY_free(pr);
  std::ostringstream oss;
  for(size_t i = 0; i < siglen; i++)
    oss << std::hex << (int)sig[i];
  std::string hexsig = oss.str();
  free(sig);
  network_message r{nm.nonce, CMD_OK, (uint16_t)hexsig.size(), hexsig};
  send_auth_and_encrypted_message(fd, r, session_key);
}

void Server::handle_getpub(int fd, const network_message& nm){
  std::string username = nm.content;
  // Check if user exists in users.txt
  std::ifstream users(USERS_FILE);
  bool found = false;
  std::string line;
  while (std::getline(users, line)) {
    std::istringstream iss(line);
    std::string uname;
    if (std::getline(iss, uname, ':')) {
      if (uname == username) {
        found = true;
        break;
      }
    }
  }
  if (!found) {
    network_message r{nm.nonce, CMD_ERROR, 0, "No such user"};
    send_auth_and_encrypted_message(fd, r, session_key);
    return;
  }
  // check for the public key file
  std::string path = KEY_DIR + username + "_pub.pem";
  std::ifstream f(path);
  if (!f.is_open()) {
    network_message r{nm.nonce, CMD_ERROR, 0, "No such user or public key"};
    send_auth_and_encrypted_message(fd, r, session_key);
    return;
  }
  std::string pub((std::istreambuf_iterator<char>(f)),
                   std::istreambuf_iterator<char>());
  network_message r{nm.nonce, CMD_OK, (uint16_t)pub.size(), pub};
  send_auth_and_encrypted_message(fd, r, session_key);
}

void Server::handle_delete(int fd, const network_message& nm){
  std::string u = nm.content;
  // Delete both private and public key files
  remove((KEY_DIR + u + "_priv.pem.enc").c_str());
  remove((KEY_DIR + u + "_pub.pem").c_str());
  network_message r{nm.nonce, CMD_OK, 0, ""};
  send_auth_and_encrypted_message(fd, r, session_key);
}
