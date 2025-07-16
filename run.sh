#!/bin/bash
# File: run.sh

# 1) Generate server RSA keys if missing
if [ ! -f keys/server_priv.pem ]; then
  echo "Generating server RSA keypair..."
  openssl genpkey -algorithm RSA \
    -out keys/server_priv.pem \
    -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout \
    -in keys/server_priv.pem \
    -out keys/server_pub.pem
fi

# 2) Build everything
make

# 3) Launch server
./dss
