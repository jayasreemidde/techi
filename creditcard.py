from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

# Constants
KEY_LENGTH = 32
IV_LENGTH = 16
SALT_LENGTH = 16
ITERATIONS = 100000

def generate_key(password: str, salt: bytes) -> bytes:
    # Use PBKDF2HMAC to derive a secure key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(plain_text: str, password: str) -> str:
    # Generate a random salt and IV
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    
    # Derive the key from the password
    key = generate_key(password, salt)
    
    # Create a Cipher object using the AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Pad the plaintext to make it a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    
    # Encrypt the padded plaintext
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Concatenate the salt, IV, and encrypted data and encode as base64
    encrypted_text = base64.b64encode(salt + iv + encrypted_data).decode()
    return encrypted_text

def decrypt(encrypted_text: str, password: str) -> str:
    # Decode the base64 encoded text
    encrypted_data = base64.b64decode(encrypted_text)
    
    # Extract the salt, IV, and encrypted message
    salt = encrypted_data[:SALT_LENGTH]
    iv = encrypted_data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    encrypted_message = encrypted_data[SALT_LENGTH + IV_LENGTH:]
    
    # Derive the key from the password
    key = generate_key(password, salt)
    
    # Create a Cipher object using the AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Decrypt the encrypted message
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_text = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plain_text.decode()

# Example usage
if __name__ == "__main__":
    password = "my_secure_password"
    credit_card_info = "1234-5678-9876-5432"
    
    encrypted_text = encrypt(credit_card_info, password)
    print(f"Encrypted: {encrypted_text}")
    
    decrypted_text = decrypt(encrypted_text, password)
    print(f"Decrypted: {decrypted_text}")
