// File: crypto.cpp
#include "crypto.h"
#include "constants.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iostream>

// -- AES-GCM -------------------------------------------------
bool gcm_encrypt(const unsigned char *pt, int pt_len,
                 const unsigned char *key,
                 unsigned char *iv, int iv_len,
                 unsigned char *&ct, int &ct_len,
                 unsigned char *&tag) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
  EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

  ct = (unsigned char*)malloc(pt_len);
  int len;
  EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len);
  ct_len = len;

  EVP_EncryptFinal_ex(ctx, ct + ct_len, &len);
  ct_len += len;

  tag = (unsigned char*)malloc(AES_GCM_TAG_SIZE);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag);

  EVP_CIPHER_CTX_free(ctx);
  return true;
}

bool gcm_decrypt(const unsigned char *ct, int ct_len,
                 const unsigned char *tag,
                 const unsigned char *key,
                 const unsigned char *iv, int iv_len,
                 unsigned char *&pt, int &pt_len) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
  EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
  
  pt = (unsigned char*)malloc(ct_len);
  int len;
  EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len);
  pt_len = len;

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, 
                      (void*)tag);
  if (EVP_DecryptFinal_ex(ctx, pt + pt_len, &len) <= 0) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  pt_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

// -- Diffie-Hellman -----------------------------------------
EVP_PKEY* generate_dh_keypair() {
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
  if (!pctx) { return NULL; }

  if (EVP_PKEY_paramgen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }

  if (EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe2048) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }

  EVP_PKEY *params = NULL;
  if (EVP_PKEY_paramgen(pctx, &params) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }

  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
  if (!kctx) { EVP_PKEY_CTX_free(pctx); EVP_PKEY_free(params); return NULL; }

  if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(kctx); EVP_PKEY_free(params); return NULL; }

  EVP_PKEY* keypair = NULL;
  if (EVP_PKEY_keygen(kctx, &keypair) <= 0) { EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(kctx); EVP_PKEY_free(params); return NULL; }

  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_free(params);
  return keypair;
}

bool derive_dh_shared_secret(EVP_PKEY *peer, EVP_PKEY *own,
                             unsigned char *&sec, size_t &seclen) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(own, NULL);
  EVP_PKEY_derive_init(ctx);
  EVP_PKEY_derive_set_peer(ctx, peer);
  EVP_PKEY_derive(ctx, NULL, &seclen);
  sec = (unsigned char*)malloc(seclen);
  EVP_PKEY_derive(ctx, sec, &seclen);
  EVP_PKEY_CTX_free(ctx);
  return true;
}

// -- RSA keypair, PEM I/O, Signing --------------------------
EVP_PKEY* generate_rsa_keypair() {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS);
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_keygen(ctx, &pkey);
  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

bool write_private_pem(EVP_PKEY *pkey, const string &path,
                       const char *pass) {
  FILE *f = fopen(path.c_str(), "wb");
  bool ok = PEM_write_PrivateKey(
    f, pkey, EVP_aes_256_cbc(), 
    (unsigned char*)pass, strlen(pass), NULL, NULL);
  fclose(f);
  return ok;
}

bool write_public_pem(EVP_PKEY *pkey, const string &path) {
  FILE *f = fopen(path.c_str(), "wb");
  bool ok = PEM_write_PUBKEY(f, pkey);
  fclose(f);
  return ok;
}

EVP_PKEY* load_private_pem(const string &path, const char *pass) {
  FILE *f = fopen(path.c_str(), "rb");
  EVP_PKEY *pkey = PEM_read_PrivateKey(
    f, NULL, NULL, (void*)pass);
  fclose(f);
  return pkey;
}

EVP_PKEY* load_public_pem(const string &path) {
  FILE *f = fopen(path.c_str(), "rb");
  EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
  fclose(f);
  return pkey;
}

bool rsa_sign(EVP_PKEY *pkey,
              const unsigned char *msg, size_t mlen,
              unsigned char *&sig, size_t &siglen) {
  EVP_MD_CTX *mctx = EVP_MD_CTX_new();
  EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey);
  EVP_DigestSignUpdate(mctx, msg, mlen);
  EVP_DigestSignFinal(mctx, NULL, &siglen);
  sig = (unsigned char*)malloc(siglen);
  EVP_DigestSignFinal(mctx, sig, &siglen);
  EVP_MD_CTX_free(mctx);
  return true;
}

bool rsa_decrypt(EVP_PKEY *priv,
                 const unsigned char* in, size_t inlen,
                 unsigned char *&out, size_t &outlen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen);
    out = (unsigned char*)malloc(outlen);
    EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool rsa_verify(
  EVP_PKEY *pkey,
  const unsigned char *msg, size_t mlen,
  const unsigned char *sig, size_t siglen) {
  EVP_MD_CTX *mctx = EVP_MD_CTX_new();
  EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey);
  EVP_DigestVerifyUpdate(mctx, msg, mlen);
  int ok = EVP_DigestVerifyFinal(mctx, sig, siglen);
  EVP_MD_CTX_free(mctx);
  return ok == 1;
}

std::string get_user_kdf_salt(const std::string& user) {
    std::ifstream f(USERS_FILE);
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string username, salt, hash, first_login, kdf_salt;
        if (std::getline(iss, username, ':') &&
            std::getline(iss, salt, ':') &&
            std::getline(iss, hash, ':') &&
            std::getline(iss, first_login, ':') &&
            std::getline(iss, kdf_salt)) {
            if (username == user) return kdf_salt;
        }
    }
    return "";
}

bool derive_user_key(const std::string& user, const std::string& password, unsigned char* key, unsigned char* iv) {
    std::string kdf_salt = get_user_kdf_salt(user);
    if (kdf_salt.empty()) return false;
    unsigned char salt_bytes[16];
    for (int i = 0; i < 16; ++i)
        salt_bytes[i] = std::stoi(kdf_salt.substr(i*2,2), nullptr, 16);

    if (!PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt_bytes, 16, 10000, 32, key))
        return false;

    RAND_bytes(iv, 16);
    return true;
}

bool aes_encrypt_pem(const std::string& in_pem, const unsigned char* key, const unsigned char* iv, std::string& out_enc) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    std::string outbuf(in_pem.size() + 32, '\0');
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, (unsigned char*)&outbuf[0], &outlen1, (const unsigned char*)in_pem.data(), in_pem.size());
    EVP_EncryptFinal_ex(ctx, (unsigned char*)&outbuf[0] + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    out_enc.assign((const char*)iv, 16); 
    out_enc.append(outbuf.data(), outlen1 + outlen2);
    return true;
}

bool aes_decrypt_pem(const std::string& in_enc, const unsigned char* key, const unsigned char* iv, std::string& out_pem) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    std::string outbuf(in_enc.size(), '\0');
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, (unsigned char*)&outbuf[0], &outlen1, (const unsigned char*)in_enc.data(), in_enc.size());
    EVP_DecryptFinal_ex(ctx, (unsigned char*)&outbuf[0] + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    out_pem.assign(outbuf.data(), outlen1 + outlen2);
    return true;
}

