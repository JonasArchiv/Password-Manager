import getpass
import json
import sys
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

MASTER_PASSWORD_FILE = 'master_password.txt'
PASSWORDS_FILE = 'passwords.json'
SALT = b'some_random_salt_'  # Change this to something unique


def load_master_password():
    try:
        with open(MASTER_PASSWORD_FILE, 'rb') as file:
            return file.read().decode().strip()
    except FileNotFoundError:
        return None


def save_master_password(master_password):
    with open(MASTER_PASSWORD_FILE, 'wb') as file:
        file.write(master_password.encode())


def get_master_password(prompt="Enter Master Password: "):
    while True:
        master_password = getpass.getpass(prompt=prompt)
        if len(master_password) < 8:
            print("Master Password must be at least 8 characters long.")
        else:
            return master_password


def generate_key(master_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def encrypt_password(key, password):
    f = Fernet(key)
    return f.encrypt(password.encode())


def decrypt_password(key, encrypted_password):
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()


def load_passwords(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def save_passwords(file_path, passwords):
    with open(file_path, 'w') as file:
        json.dump(passwords, file)


def add_password(file_path, key, site, password):
    passwords = load_passwords(file_path)
    passwords[site] = encrypt_password(key, password).decode()
    save_passwords(file_path, passwords)


def get_password(file_path, key, site):
    passwords = load_passwords(file_path)
    if site in passwords:
        return decrypt_password(key, passwords[site].encode())
    else:
        return None


def delete_password(file_path, key, site):
    passwords = load_passwords(file_path)
    if site in passwords:
        del passwords[site]
        save_passwords(file_path, passwords)


def update_password(file_path, key, site, new_password):
    passwords = load_passwords(file_path)
    if site in passwords:
        passwords[site] = encrypt_password(key, new_password).decode()
        save_passwords(file_path, passwords)
        print("Password updated successfully.")
    else:
        print("No password found for the specified site.")


def change_master_password():
    current_master_password = get_master_password("Enter Current Master Password: ")
    if current_master_password == load_master_password():
        new_master_password = get_master_password("Enter New Master Password: ")
        save_master_password(new_master_password)
        print("Master Password changed successfully.")
    else:
        print("Incorrect current Master Password.")


def list_passwords(file_path, key):
    passwords = load_passwords(file_path)
    if passwords:
        print("List of stored passwords:")
        for site, encrypted_password in passwords.items():
            decrypted_password = decrypt_password(key, encrypted_password.encode())
            print(f"Site: {site} | Password: {decrypted_password}")
    else:
        print("No passwords stored yet.")


def main():
    parser = argparse.ArgumentParser(description="Simple Password Manager")
    parser.add_argument('action', choices=['add', 'get', 'delete', 'update', 'change_master', 'list'], help="Action to perform")
    parser.add_argument('site', help="Website or service name")
    parser.add_argument('--password', help="Password to store or update")
    args = parser.parse_args()

    if args.action == 'change_master':
        change_master_password()
        return
    elif args.action == 'list':
        master_password = load_master_password()
        if master_password:
            key = generate_key(master_password)
            list_passwords(PASSWORDS_FILE, key)
        else:
            print("Master password not set. Use 'change_master' action to set it.")
        return

    master_password = load_master_password()
    if not master_password:
        master_password = get_master_password()
        save_master_password(master_password)

    key = generate_key(master_password)

    if args.action == 'add':
        if args.password:
            add_password(PASSWORDS_FILE, key, args.site, args.password)
            print("Password added successfully.")
        else:
            print("Password is required to add a new entry.")
    elif args.action == 'get':
        password = get_password(PASSWORDS_FILE, key, args.site)
        if password:
            print(f"Password for {args.site}: {password}")
        else:
            print("No password found for the specified site.")
    elif args.action == 'delete':
        delete_password(PASSWORDS_FILE, key, args.site)
        print("Password deleted successfully.")
    elif args.action == 'update':
        if args.password:
            update_password(PASSWORDS_FILE, key, args.site, args.password)
        else:
            print("New password is required to update an entry.")


if __name__ == "__main__":
    main()
