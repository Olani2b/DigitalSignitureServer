// File: constants.h
#pragma once

// ---- Command IDs ----
#define CREATEKEYS_COMMAND   1
#define SIGN_COMMAND         2
#define GETPUB_COMMAND       3
#define DELETE_COMMAND       4
#define CMD_CHANGE_PASSWORD   12
#define CMD_SERVER_AUTH       20

#define CMD_OK               10
#define CMD_ERROR            11

// ---- Crypto parameters ----
#define AES_KEY_SIZE         16  
#define AES_GCM_IV_SIZE      12
#define AES_GCM_TAG_SIZE     16
#define DH_KEY_SIZE          2048
#define RSA_KEY_BITS         2048

// ---- Network ----
#define PORT                 5252
#define NONCE_MAX            65535
#define BUF_LEN              4096

// ---- User storage ----
#define USERS_FILE           "users.txt" 
#define KEY_DIR              "keys/"
#define KEYFILE_PASSPHRASE   "secret123"  // for encrypting PEM
