// File: server.h
#pragma once
#include <vector>
#include <map>
#include <openssl/evp.h>
#include "utility.h"

class Server {
  int listen_fd, port;
  unsigned char session_key[AES_KEY_SIZE];
  EVP_PKEY *dh_priv, *dh_peer;
  std::map<std::string,bool> authenticated;
  std::map<std::string,std::string> user_passwords;
  std::map<std::string, uint16_t> last_seen_nonce; // For replay protection

  // Helper storage:
  bool load_users();
  bool verify_password(const std::string& u, const std::string& p);
  bool update_password(const std::string& u, const std::string& p);

  // Operations:
  void handle_createkeys(int fd, const network_message&);
  void handle_signdoc(int fd, const network_message&);
  void handle_getpub(int fd, const network_message&);
  void handle_delete(int fd, const network_message&);

public:
  Server(int port);
  void start();
};
