import secrets
import time
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import base64
import os
import json

# Character sets
LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SPECIAL = "!@#$%^&*()_+"

# Function to generate a password
def generate_password(length, use_upper, use_digits, use_special):
    character_pool = LOWER  # Always include lowercase letters

    # Add character sets based on user input
    if use_upper:
        character_pool += UPPER
    if use_digits:
        character_pool += DIGITS
    if use_special:
        character_pool += SPECIAL

    # Generate the password by selecting characters from the pool
    password = ''.join(secrets.choice(character_pool) for _ in range(length))
    
    return password

# Input validation function
def get_valid_length():
    while True:
        try:
            length = int(input("Enter the length of the password (must be a positive integer): "))
            if length > 0:
                return length
            else:
                print("Please enter a positive number.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

def get_yes_no_input(prompt):
    while True:
        response = input(prompt).lower()
        if response in ["y", "n"]:
            return response == "y"
        else:
            print("Please enter 'y' for yes or 'n' for no.")

# Function for the animated '...'
def show_loading_animation(duration=3):
    print("Generating password", end="")
    for _ in range(duration * 3):  # 3 dots per second
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.33)  # Sleep for 1/3 of a second
    print()  # Move to the next line after the animation

# Key derivation from master password
def derive_key_from_master(master_password):
    salt = load_salt()
    if salt is None:
        salt = generate_salt()
        save_salt(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

# Salt management
def generate_salt():
    return os.urandom(16)  # Generate a 16-byte salt

def save_salt(salt, file_path='salt.json'):
    with open(file_path, 'w') as file:
        json.dump({'salt': base64.urlsafe_b64encode(salt).decode()}, file)

def load_salt(file_path='salt.json'):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            return base64.urlsafe_b64decode(data['salt'])
    except (FileNotFoundError, json.JSONDecodeError):
        return None

# Encryption and decryption
def encrypt_password(password, encryption_key):
    fernet = Fernet(encryption_key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password.decode()

def decrypt_password(encrypted_password, encryption_key):
    fernet = Fernet(encryption_key)
    decrypted_password = fernet.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

# Adding password to JSON file
def add_password(account, username, password, key, file_path='passwords.json'):
    encrypted_password = encrypt_password(password, key)
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    if account in data:
        overwrite = get_yes_no_input(f"Account '{account}' already exists. Do you want to overwrite it? (y/n): ")
        if not overwrite:
            return

    data[account] = {'username': username, 'password': encrypted_password}

    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

# Retrieving password
def retrieve_password(account, key, file_path='passwords.json'):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    
    if account in data:
        encrypted_password = data[account]['password']
        return decrypt_password(encrypted_password, key)
    else:
        return None

# Deleting a password from JSON file
def delete_password(account, file_path='passwords.json'):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        print("No accounts found.")
        return

    if account in data:
        confirm = get_yes_no_input(f"Are you sure you want to delete the password for '{account}'? (y/n): ")
        if confirm:
            del data[account]
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
            print(f"Password for '{account}' has been deleted.")
        else:
            print("Deletion canceled.")
    else:
        print(f"Account '{account}' not found.")

# List all accounts
def list_accounts(file_path='passwords.json'):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    return list(data.keys())

# Login or set up a master password
def verify_master_password(input_password, file_path='master_password.json'):
    salt, stored_hashed_password = load_master_password_hash(file_path)
    if salt is None or stored_hashed_password is None:
        print("Master password not set. Setting up a new master password.")
        save_master_password_hash(input_password)
        return True

    # Hash the input password with the same salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    input_hashed_password = base64.urlsafe_b64encode(kdf.derive(input_password.encode()))

    # Compare the hashed input password with the stored hashed password
    return input_hashed_password.decode() == stored_hashed_password

# Save master password hash and salt
def save_master_password_hash(master_password, file_path='master_password.json'):
    salt = generate_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed_password = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    # Store the salt and hashed password
    data = {
        'salt': base64.urlsafe_b64encode(salt).decode(),
        'hashed_password': hashed_password.decode()
    }

    with open(file_path, 'w') as file:
        json.dump(data, file)

# Load stored master password hash and salt
def load_master_password_hash(file_path='master_password.json'):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            salt = base64.urlsafe_b64decode(data['salt'])
            hashed_password = data['hashed_password']
            return salt, hashed_password
    except FileNotFoundError:
        return None, None

# Login flow to validate master password
def login():
    master_password = input("Enter your master password: ")

    if verify_master_password(master_password):
        print("Login successful.")
        return derive_key_from_master(master_password)
    else:
        print("Login failed. Incorrect master password.")
        return None

if __name__ == '__main__':
    # Login or setup master password
    encryption_key = login()
    
    if encryption_key:
        while True:
            print("\nOptions:")
            print("1. Generate a new password")
            print("2. Add password to manager")
            print("3. Retrieve password")
            print("4. Delete password")
            print("5. List all accounts")
            print("6. Quit")

            option = input("Select an option (1-6): ")

            if option == '1':
                # Generate a new password
                length = get_valid_length()
                use_upper = get_yes_no_input("Do you want uppercase letters in the password? (y/n): ")
                use_digits = get_yes_no_input("Do you want digits in the password? (y/n): ")
                use_special = get_yes_no_input("Do you want special characters in the password? (y/n): ")

                # Show loading animation
                show_loading_animation()

                # Generate and display the password
                password = generate_password(length, use_upper, use_digits, use_special)
                print(f"Your password is: {password}")

            elif option == '2':
                # Add password to manager
                account = input("Enter the account name: ")
                username = input(f"Enter the username for {account}: ")
                password = input(f"Enter the password for {account}: ")

                # Add the password to the manager (JSON file)
                add_password(account, username, password, encryption_key)
                print(f"Password for {account} has been added.")

            elif option == '3':
                # Retrieve password from manager
                account = input("Enter the account name to retrieve the password: ")
                retrieved_password = retrieve_password(account, encryption_key)

                if retrieved_password:
                    print(f"Password for {account}: {retrieved_password}")
                else:
                    print(f"Account '{account}' not found.")

            elif option == '4':
                # Delete password from manager
                account = input("Enter the account name to delete the password: ")
                delete_password(account)

            elif option == '5':
                # List all stored accounts
                accounts = list_accounts()
                if accounts:
                    print("Stored accounts:")
                    for acc in accounts:
                        print(f" - {acc}")
                else:
                    print("No accounts found.")

            elif option == '6':
                # Quit the program
                print("Exiting...")
                break
            else:
                print("Invalid option, please select a valid number (1-5).")
