import os
import secrets
import ast
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from tkinter import Tk
from tkinter.filedialog import askopenfilename

# Elliptic curve parameters (NIST P-256 curve)
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F4A13945D898C296
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

KEY_FOLDER = "keys"
SAFE_FOLDER = "safe"
SAFE_FILE = "safe_container.safe"

# Ensure the necessary folders exist
def ensure_folders():
    os.makedirs(KEY_FOLDER, exist_ok=True)
    os.makedirs(SAFE_FOLDER, exist_ok=True)

# Generate a private/public key pair and save them to files
def generate_keys():
    ensure_folders()
    private_key = secrets.randbelow(n - 1) + 1
    public_key = scalar_multiplication(private_key, (Gx, Gy))

    with open(os.path.join(KEY_FOLDER, "private_key.txt"), "w") as priv_file:
        priv_file.write(hex(private_key))

    with open(os.path.join(KEY_FOLDER, "public_key.txt"), "w") as pub_file:
        pub_file.write(f"{hex(public_key[0])},{hex(public_key[1])}")

    print(f"Keys generated and saved to {KEY_FOLDER}/")

# Elliptic curve point addition
def point_addition(P, Q):
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P

    x1, y1 = P
    x2, y2 = Q

    if P != Q:
        m = (y2 - y1) * pow(x2 - x1, -1, p) % p
    else:
        m = (3 * x1**2 + a) * pow(2 * y1, -1, p) % p

    x3 = (m**2 - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return x3, y3

# Elliptic curve scalar multiplication using double-and-add algorithm
def scalar_multiplication(k, P):
    R = (0, 0)
    for bit in bin(k)[2:]:
        R = point_addition(R, R)
        if bit == '1':
            R = point_addition(R, P)
    return R

# AES encryption with PKCS7 padding
def aes_encrypt(key, plaintext):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# AES decryption with PKCS7 unpadding
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data

# Move a file to the safe folder using a file dialog
def move_file_to_safe():
    Tk().withdraw()  # Hide the root Tk window
    file_path = askopenfilename(title="Select a file to move to the safe")
    if not file_path:
        print("No file selected.")
        return

    try:
        shutil.move(file_path, SAFE_FOLDER)
        print(f"File moved to {SAFE_FOLDER}/")
    except Exception as e:
        print(f"Error moving file: {e}")

# Encrypt the safe folder into a .safe file and remove the folder
def encrypt_safe():
    safe_files = os.listdir(SAFE_FOLDER)
    if not safe_files:
        print("Safe is empty. Nothing to encrypt.")
        return

    key = secrets.token_bytes(32)  # Generate a random 256-bit key

    safe_data = b""
    for file_name in safe_files:
        file_path = os.path.join(SAFE_FOLDER, file_name)
        with open(file_path, "rb") as f:
            safe_data += file_name.encode('utf-8') + b"\n" + f.read() + b"\n\n"  # Store file names

    encrypted_safe = aes_encrypt(key, safe_data)

    with open(SAFE_FILE, "wb") as f:
        f.write(key + encrypted_safe)

    print("Safe encrypted and saved as safe_container.safe")

    # Remove the safe folder after encryption
    shutil.rmtree(SAFE_FOLDER)
    print(f"{SAFE_FOLDER} folder removed after encryption.")

# Decrypt the .safe file and restore the folder with original files
def decrypt_safe():
    if not os.path.exists(SAFE_FILE):
        print("Safe file not found.")
        return

    try:
        with open(SAFE_FILE, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading safe file: {e}")
        return

    key = data[:32]
    encrypted_data = data[32:]

    decrypted_data = aes_decrypt(key, encrypted_data)

    # Restore the safe folder
    os.makedirs(SAFE_FOLDER, exist_ok=True)
    files = decrypted_data.split(b"\n\n")
    for file in files:
        if file:
            parts = file.split(b"\n", 1)
            if len(parts) == 2:
                file_name = parts[0].decode('utf-8')
                file_content = parts[1]
                with open(os.path.join(SAFE_FOLDER, file_name), "wb") as f:
                    f.write(file_content)

    print(f"Safe unlocked and files restored to {SAFE_FOLDER}/")

# Text-based menu
def menu():
    while True:
        print("\n==== ECC Encryption Menu ====")
        print("1. Generate Keys")
        print("2. Move File to Safe")
        print("3. Encrypt Safe")
        print("4. Decrypt Safe")
        print("5. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            generate_keys()
        elif choice == "2":
            move_file_to_safe()
        elif choice == "3":
            encrypt_safe()
        elif choice == "4":
            decrypt_safe()
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")

# Ensure necessary folders exist on startup
ensure_folders()

# Run the text-based menu
menu()
