// File: utility.h
#pragma once
#include <string>
#include <arpa/inet.h>
#include "constants.h"
using std::string;

struct network_message {
  uint16_t nonce;
  uint8_t  command;
  uint16_t content_length;
  string   content;
};

bool send_raw(int fd, const unsigned char *buf, int len);
bool recv_raw(int fd, unsigned char *buf, int len);

// wrappers for GCM: iv||tag||ciphertext
bool send_message_gcm(
  int fd, const unsigned char *plaintext, int pt_len,
  const unsigned char *key);

bool receive_message_gcm(
  int fd, unsigned char *&plaintext, int &pt_len,
  const unsigned char *key);

// Authenticated: prepend HMAC or reuse GCM
bool send_auth_and_encrypted_message(
  int fd, const network_message &msg,
  const unsigned char *session_key);

bool receive_auth_and_encrypted_message(
  int fd, network_message &msg,
  const unsigned char *session_key);

string nm_to_string(const network_message &msg);
network_message string_to_nm(const string &s);
