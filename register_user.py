import hashlib, os, sys

def hexstr(b): return b.hex()

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

if len(sys.argv) != 3:
    print("Usage: python3 register_user.py <username> <password>")
    sys.exit(1)

username, password = sys.argv[1], sys.argv[2]
salt = hexstr(os.urandom(16))
password_hash = hash_password(password, salt)
first_login_flag = "1"

with open("users.txt", "a") as f:
    f.write(f"{username}:{salt}:{password_hash}:{first_login_flag}\n")

print(f"User {username} registered.") 