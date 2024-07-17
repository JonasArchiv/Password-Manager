from cryptography.fernet import Fernet
import getpass, json, sys, argparse


def generate_key(password):
    return Fernet.generate_key()


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


def main():
    parser = argparse.ArgumentParser(description="Simple Password Manager")
    parser.add_argument('action', choices=['add', 'get', 'delete'], help="Action to perform")
    parser.add_argument('site', help="Website or service name")
    parser.add_argument('--password', help="Password to store or update", default=None)
    args = parser.parse_args()

    master_password = getpass.getpass(prompt="Enter Master Password: ")
    key = generate_key(master_password)
    file_path = 'passwords.json'

    if args.action == 'add':
        if args.password:
            add_password(file_path, key, args.site, args.password)
            print("Password added successfully.")
        else:
            print("Password is required to add a new entry.")
    elif args.action == 'get':
        password = get_password(file_path, key, args.site)
        if password:
            print(f"Password for {args.site}: {password}")
        else:
            print("No password found for the specified site.")
    elif args.action == 'delete':
        delete_password(file_path, key, args.site)
        print("Password deleted successfully.")


if __name__ == "__main__":
    main()
