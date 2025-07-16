# Digital Signature Server (DSS)

A secure client-server system for digital signatures, supporting user registration, authentication, key management, and document signing. All communication is encrypted and authenticated.

---

## Prerequisites

- **C++11 or newer**
- **OpenSSL development libraries**  
  (e.g., `libssl-dev` on Ubuntu/Debian)
- **make** utility

---

## Initial Setup

### 1. Run the Setup Script

You can use the provided script to generate the server's RSA keypair (if missing), build the project, and start the server:

```sh
./run.sh
```

This will:
- Create the `keys/server_priv.pem` and `keys/server_pub.pem` files if they do not exist.
- Build all necessary executables.
- Start the server.

### 2. Register Users

Before a user can log in, they must be registered by an administrator.  
Run the registration tool for each user (in a **separate terminal**):

```sh
./register_user <username> <password>
```

This will append the user to `users.txt` and set their initial password.

---

## Running the System

### 1. Start the Server

If you used `./run.sh`, the server is already running.  
Otherwise, you can start it manually:

```sh
./dss
```

### 2. Start the Client

In a **separate terminal**, run:

```sh
./client
```

You will be prompted for the server address, port, and your username.

---

## Usage

- **create**: Generate your personal key pair (run after first login)
- **sign <file>**: Digitally sign a document (file contents or literal string)
- **getpub <user>**: Get a user's public key
- **delete**: Delete your key pair
- **help**: Show help menu
- **exit**: Quit the application

---

## Notes

- The `users.txt` file and `keys/` directory must be in the same directory as the executables.
- The server will create the `keys/` directory if it does not exist.
- Each user must change their password on first login.
- All communication is encrypted using Diffie-Hellman and AES-GCM.

---

## Cleaning Up

To remove all built files:

```sh
make clean
```

---

## Troubleshooting

- **OpenSSL errors**: Ensure you have the OpenSSL development libraries installed.
- **Authentication errors**: Make sure the user is registered and the correct password is used.
- **Server key errors**: Ensure the server keypair is generated and present in the `keys/` directory.

---

