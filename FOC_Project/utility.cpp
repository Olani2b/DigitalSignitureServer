// File: utility.cpp
#include "utility.h"
#include "crypto.h"
#include <unistd.h>
#include <vector>
#include <cstring>
#include <openssl/rand.h>


// Simple raw send/recv
bool send_raw(int fd, const unsigned char *buf, int len) {
  int sent = 0;
  while(sent < len) {
    int n = write(fd, buf+sent, len-sent);
    if(n<=0) return false;
    sent += n;
  }
  return true;
}

bool recv_raw(int fd, unsigned char *buf, int len) {
  int rec = 0;
  while(rec < len) {
    int n = read(fd, buf+rec, len-rec);
    if(n<=0) return false;
    rec += n;
  }
  return true;
}

// Send:  [uint16_t iv_len][iv][uint16_t tag_len][tag][uint32_t ct_len][ct]
bool send_message_gcm(int fd, const unsigned char *pt, int pt_len,
                      const unsigned char *key) {
  unsigned char iv[AES_GCM_IV_SIZE];
  RAND_bytes(iv, AES_GCM_IV_SIZE);
  unsigned char *ct, *tag;
  int ct_len;
  gcm_encrypt(pt, pt_len, key, iv, AES_GCM_IV_SIZE,
              ct, ct_len, tag);
  uint16_t ivl = AES_GCM_IV_SIZE,
           tgl = AES_GCM_TAG_SIZE;
  uint32_t ctl = ct_len;
  send_raw(fd, (unsigned char*)&ivl, sizeof(ivl));
  send_raw(fd, iv, ivl);
  send_raw(fd, (unsigned char*)&tgl, sizeof(tgl));
  send_raw(fd, tag, tgl);
  send_raw(fd, (unsigned char*)&ctl, sizeof(ctl));
  send_raw(fd, ct, ct_len);
  free(ct); free(tag);
  return true;
}

bool receive_message_gcm(int fd, unsigned char *&pt, int &pt_len,
                         const unsigned char *key) {
  uint16_t ivl, tgl; uint32_t ctl;
  recv_raw(fd, (unsigned char*)&ivl, sizeof(ivl));
  unsigned char iv[ivl]; recv_raw(fd, iv, ivl);
  recv_raw(fd, (unsigned char*)&tgl, sizeof(tgl));
  unsigned char tag[tgl]; recv_raw(fd, tag, tgl);
  recv_raw(fd, (unsigned char*)&ctl, sizeof(ctl));
  unsigned char *ct = (unsigned char*)malloc(ctl);
  recv_raw(fd, ct, ctl);
  bool ok = gcm_decrypt(ct, ctl, tag, key, iv, ivl, pt, pt_len);
  free(ct);
  return ok;
}

// Serialize network_message to a single string: [nonce|cmd|len|content]
string nm_to_string(const network_message &m) {
  string s;
  s.append((char*)&m.nonce, sizeof(m.nonce));
  s.push_back((char)m.command);
  s.append((char*)&m.content_length, sizeof(m.content_length));
  s += m.content;
  return s;
}
network_message string_to_nm(const string &s) {
  network_message m;
  int idx=0;
  memcpy(&m.nonce, s.data()+idx, 2); idx+=2;
  m.command = (uint8_t)s[idx++];
  memcpy(&m.content_length, s.data()+idx, 2); idx+=2;
  m.content = s.substr(idx, m.content_length);
  return m;
}

bool send_auth_and_encrypted_message(
  int fd, const network_message &msg,
  const unsigned char *session_key) {
  string raw = nm_to_string(msg);
  return send_message_gcm(fd, (unsigned char*)raw.data(), raw.size(), session_key);
}

bool receive_auth_and_encrypted_message(
  int fd, network_message &msg,
  const unsigned char *session_key) {
  unsigned char *pt; int pt_len;
  if(!receive_message_gcm(fd, pt, pt_len, session_key))
    return false;
  string s((char*)pt, pt_len);
  msg = string_to_nm(s);
  free(pt);
  return true;
}
