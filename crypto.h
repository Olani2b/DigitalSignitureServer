// File: crypto.h
#pragma once
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
using std::string;

// -- AES-GCM --
bool gcm_encrypt(
  const unsigned char *plaintext, int plaintext_len,
  const unsigned char *key,
  unsigned char *iv, int iv_len,
  unsigned char *&ciphertext, int &cipher_len,
  unsigned char *&tag);

bool gcm_decrypt(
  const unsigned char *ciphertext, int ciphertext_len,
  const unsigned char *tag,
  const unsigned char *key,
  const unsigned char *iv, int iv_len,
  unsigned char *&plaintext, int &plain_len);

// -- Diffie-Hellman --
EVP_PKEY* generate_dh_keypair();
bool derive_dh_shared_secret(
  EVP_PKEY *peerkey, EVP_PKEY *ownkey,
  unsigned char *&secret, size_t &secret_len);

// -- RSA Key-Generation & Signing --
EVP_PKEY* generate_rsa_keypair();
bool write_private_pem(
  EVP_PKEY *pkey, const string &path, const char *pass);
bool write_public_pem(EVP_PKEY *pkey, const string &path);
EVP_PKEY* load_private_pem(const string &path, const char *pass);
EVP_PKEY* load_public_pem(const string &path);

bool rsa_sign(
  EVP_PKEY *pkey,
  const unsigned char *msg, size_t mlen,
  unsigned char *&sig, size_t &siglen);

bool rsa_decrypt(
  EVP_PKEY *priv, const unsigned char* in, size_t inlen,
  unsigned char *&out, size_t &outlen);

bool rsa_verify(
  EVP_PKEY *pkey,
  const unsigned char *msg, size_t mlen,
  const unsigned char *sig, size_t siglen);

bool derive_user_key(const std::string& user, const std::string& password, unsigned char* key, unsigned char* iv);
bool aes_encrypt_pem(const std::string& in_pem, const unsigned char* key, const unsigned char* iv, std::string& out_enc);
bool aes_decrypt_pem(const std::string& in_enc, const unsigned char* key, const unsigned char* iv, std::string& out_pem);
std::string get_user_kdf_salt(const std::string& user);
