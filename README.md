What is Onion Peeling Encryption?
- A multi-layer encryption mechanism.
- Inspired by the structure of an onion – multiple layers wrapped around the core.
- Ensures robust data security by encrypting data in sequential layers, each requiring a unique key.

Key Features:
- Layered Encryption & Decryption.
- Protects data even if one layer is compromised.
- Common in systems like Tor for anonymity and privacy.

![image](https://github.com/user-attachments/assets/b1517e64-7929-4bf6-be80-2781feec9e35)

Libraries and Tools Used:
1. Cryptography Package:
   - Cipher, algorithms, modes for encryption/decryption.
   - PBKDF2HMAC for secure key derivation.
   - PKCS7 for padding.
2. Randomness and Security:
   - os.urandom() for generating Initialization Vectors (IVs) and salts.
3. Default Backend:
   - Provides platform-specific cryptographic functionalities.
![image](https://github.com/user-attachments/assets/a1d9369d-9119-4685-b9ca-448709199c36)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os

def generate_key(password: bytes, salt: bytes) -> bytes:
    """Generate a symmetric key using a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def encrypt_layer(data: bytes, key: bytes) -> bytes:
    """Encrypt data using a symmetric key."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_layer(data: bytes, key: bytes) -> bytes:
    """Decrypt data using a symmetric key."""
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(data[16:]) + decryptor.finalize()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def onion_encrypt(data: bytes, keys: list) -> bytes:
    """Apply multiple layers of encryption."""
    encrypted_data = data
    for key in keys:
        encrypted_data = encrypt_layer(encrypted_data, key)
    return encrypted_data

def onion_decrypt(data: bytes, keys: list) -> bytes:
    """Remove layers of encryption."""
    decrypted_data = data
    for key in reversed(keys):
        decrypted_data = decrypt_layer(decrypted_data, key)
    return decrypted_data

# Simulation
if __name__ == "__main__":
    message = b"Hello, 5G World!"
    passwords = [b"password1", b"password2", b"password3"]
    salts = [os.urandom(16) for _ in passwords]
    keys = [generate_key(password, salt) for password, salt in zip(passwords, salts)]

    # Onion encryption
    print("Original Message:", message)
    encrypted_message = onion_encrypt(message, keys)
    print("Encrypted Message:", encrypted_message.hex())

    # Onion decryption
    decrypted_message = onion_decrypt(encrypted_message, keys)
    print("Decrypted Message:", decrypted_message)


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os

def generate_key(password: bytes, salt: bytes) -> bytes:
    """Generate a symmetric key using a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def encrypt_layer(data: bytes, key: bytes) -> bytes:
    """Encrypt data using a symmetric key."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_layer(data: bytes, key: bytes) -> bytes:
    """Decrypt data using a symmetric key."""
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(data[16:]) + decryptor.finalize()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def onion_encrypt(data: bytes, keys: list) -> bytes:
    """Apply multiple layers of encryption."""
    encrypted_data = data
    for key in keys:
        encrypted_data = encrypt_layer(encrypted_data, key)
    return encrypted_data

def onion_decrypt(data: bytes, keys: list) -> bytes:
    """Remove layers of encryption."""
    decrypted_data = data
    for key in reversed(keys):
        decrypted_data = decrypt_layer(decrypted_data, key)
    return decrypted_data

def simulate_sending_and_receiving():
    """Simulate sending and receiving data samples with encryption and decryption."""
    samples = [
        b"Message 1: Secure communication.",
        b"Message 2: Onion encryption is powerful!",
        b"Message 3: Cryptography ensures confidentiality.",
        b"Message 4: Federated learning in edge cloud.",
        b"Message 5: Blockchain-based secure messaging."
    ]

    passwords = [b"password1", b"password2", b"password3"]
    salts = [os.urandom(16) for _ in passwords]
    keys = [generate_key(password, salt) for password, salt in zip(passwords, salts)]

    encrypted_samples = []
    print("\n--- Encrypting and Sending ---")
    for sample in samples:
        encrypted_sample = onion_encrypt(sample, keys)
        encrypted_samples.append(encrypted_sample)
        print(f"Original: {sample}")
        print(f"Encrypted: {encrypted_sample.hex()}\n")

    print("\n--- Receiving and Decrypting ---")
    for encrypted_sample in encrypted_samples:
        decrypted_sample = onion_decrypt(encrypted_sample, keys)
        print(f"Encrypted: {encrypted_sample.hex()}")
        print(f"Decrypted: {decrypted_sample}\n")

# Simulation
if __name__ == "__main__":
    simulate_sending_and_receiving()

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import csv

def generate_key(password: bytes, salt: bytes) -> bytes:
    """Generate a symmetric key using a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def encrypt_layer(data: bytes, key: bytes) -> bytes:
    """Encrypt data using a symmetric key."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_layer(data: bytes, key: bytes) -> bytes:
    """Decrypt data using a symmetric key."""
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(data[16:]) + decryptor.finalize()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def onion_encrypt(data: bytes, keys: list) -> bytes:
    """Apply multiple layers of encryption."""
    encrypted_data = data
    for key in keys:
        encrypted_data = encrypt_layer(encrypted_data, key)
    return encrypted_data

def onion_decrypt(data: bytes, keys: list) -> bytes:
    """Remove layers of encryption."""
    decrypted_data = data
    for key in reversed(keys):
        decrypted_data = decrypt_layer(decrypted_data, key)
    return decrypted_data

def simulate_sending_and_receiving_with_csv():
    """Simulate sending and receiving data samples with encryption and decryption, and save results to CSV."""
    samples = [
        b"Message 1: Secure communication.",
        b"Message 2: Onion encryption is powerful!",
        b"Message 3: Cryptography ensures confidentiality.",
        b"Message 4: Federated learning in edge cloud.",
        b"Message 5: Blockchain-based secure messaging."
    ]

    passwords = [b"password1", b"password2", b"password3"]
    salts = [os.urandom(16) for _ in passwords]
    keys = [generate_key(password, salt) for password, salt in zip(passwords, salts)]

    encrypted_samples = []
    decrypted_samples = []

    print("\n--- Encrypting and Sending ---")
    for sample in samples:
        encrypted_sample = onion_encrypt(sample, keys)
        encrypted_samples.append(encrypted_sample)
        print(f"Original: {sample}")
        print(f"Encrypted: {encrypted_sample.hex()}\n")

    print("\n--- Receiving and Decrypting ---")
    for encrypted_sample in encrypted_samples:
        decrypted_sample = onion_decrypt(encrypted_sample, keys)
        decrypted_samples.append(decrypted_sample)
        print(f"Encrypted: {encrypted_sample.hex()}")
        print(f"Decrypted: {decrypted_sample}\n")

    # Save communication details to CSV
    with open("communication_log.csv", "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Original Message", "Encrypted Message", "Decrypted Message"])
        for original, encrypted, decrypted in zip(samples, encrypted_samples, decrypted_samples):
            csvwriter.writerow([original.decode('utf-8'), encrypted.hex(), decrypted.decode('utf-8')])

    print("Communication log saved to communication_log.csv")

# Simulation
if __name__ == "__main__":
    simulate_sending_and_receiving_with_csv()


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import csv

def generate_key(password: bytes, salt: bytes) -> bytes:
    """Generate a symmetric key using a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def encrypt_layer(data: bytes, key: bytes) -> bytes:
    """Encrypt data using a symmetric key."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_layer(data: bytes, key: bytes) -> bytes:
    """Decrypt data using a symmetric key."""
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(data[16:]) + decryptor.finalize()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def onion_encrypt(data: bytes, keys: list) -> bytes:
    """Apply multiple layers of encryption."""
    encrypted_data = data
    for key in keys:
        encrypted_data = encrypt_layer(encrypted_data, key)
    return encrypted_data

def onion_decrypt(data: bytes, keys: list) -> bytes:
    """Remove layers of encryption."""
    decrypted_data = data
    for key in reversed(keys):
        decrypted_data = decrypt_layer(decrypted_data, key)
    return decrypted_data

def simulate_sending_and_receiving_with_csv():
    """Simulate sending and receiving data samples with encryption and decryption, and save results to CSV."""
    samples = [
        b"Message 1: Secure communication.",
        b"Message 2: Onion encryption is powerful!",
        b"Message 3: Cryptography ensures confidentiality.",
        b"Message 4: Federated learning in edge cloud.",
        b"Message 5: Blockchain-based secure messaging."
    ]

    passwords = [b"password1", b"password2", b"password3"]
    salts = [os.urandom(16) for _ in passwords]
    keys = [generate_key(password, salt) for password, salt in zip(passwords, salts)]

    encrypted_samples = []
    decrypted_samples = []

    print("\n--- Encrypting and Sending ---")
    for sample in samples:
        encrypted_sample = onion_encrypt(sample, keys)
        encrypted_samples.append(encrypted_sample)
        print(f"Original: {sample}")
        print(f"Encrypted: {encrypted_sample.hex()}\n")

    print("\n--- Receiving and Decrypting ---")
    for encrypted_sample in encrypted_samples:
        decrypted_sample = onion_decrypt(encrypted_sample, keys)
        decrypted_samples.append(decrypted_sample)
        print(f"Encrypted: {encrypted_sample.hex()}")
        print(f"Decrypted: {decrypted_sample}\n")

    # Save communication details to CSV
    with open("communication_log.csv", "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Original Message", "Encrypted Message", "Decrypted Message"])
        for original, encrypted, decrypted in zip(samples, encrypted_samples, decrypted_samples):
            csvwriter.writerow([original.decode('utf-8'), encrypted.hex(), decrypted.decode('utf-8')])

    print("Communication log saved to communication_log.csv")

# Simulation
if __name__ == "__main__":
    simulate_sending_and_receiving_with_csv()


