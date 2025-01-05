# ECC-Container

# A Simple ECC-Based File Encryption Container

This App is a lightweight, easy-to-use file encryption tool built with Python. It leverages **Elliptic Curve Cryptography (ECC)** for key management and **AES encryption** to secure files within a digital safe container.

This tool allows users to:
- Generate ECC key pairs.
- Move files into a safe (container).
- Encrypt the entire safe into a `.safe` file.
- Decrypt the `.safe` file to restore the original files.

---

## Features
- **ECC Key Management**: Secure key generation using NIST P-256 curve.
- **AES Encryption**: Uses AES-256 encryption to secure your safe.
- **Simple Interface**: Text-based menu with file explorer for selecting files.
- **Secure Safe Container**: All files are encrypted into a single `.safe` container file.
- You can only store text files for now, adding more to this project soon.

---

## How to Use

### 1. Clone the Repository:
```bash
git clone https://github.com/reschjonas/ECC-Container.git
cd ECC-Container
(or just download the zip file)
```

### 2. Install Dependencies:
The project uses built-in Python libraries. No additional installation is needed.

### 3. Run the Application:
```bash
python Encryption_Console.py
```

---

## Menu Options Overview
| Option                | Description                                          |
|-----------------------|------------------------------------------------------|
| 1. Generate Keys       | Creates an ECC key pair and saves them in the `keys/` folder. |
| 2. Move File to Safe   | Opens a file explorer to select a file to move into the `safe/` folder. |
| 3. Encrypt Safe        | Encrypts all files in the `safe/` folder into a `.safe` container and removes the folder. |
| 4. Decrypt Safe        | Decrypts the `.safe` container and restores the files in the `safe/` folder. |
| 5. Exit                | Exits the application.                               |

---

## File Types Explained
| File Type        | Description                                 |
|------------------|---------------------------------------------|
| `.txt`           | Plain text files you want to secure.        |
| `.safe`          | Encrypted container file storing multiple files. |

---

## Security Details
- **ECC Key Pair**: A secure key pair is generated for encrypting and decrypting the safe.
- **AES Encryption**: The safe container is encrypted using a randomly generated 256-bit AES key.

---

## Example Workflow

### Step 1: Generate Keys
Run the tool and select **1. Generate Keys** to create your ECC key pair.

### Step 2: Move Files to Safe
Select **2. Move File to Safe** and choose a file from your computer to move to the `safe/` folder.

### Step 3: Encrypt Safe
Select **3. Encrypt Safe** to secure all files in the `safe/` folder into a `.safe` container.

### Step 4: Decrypt Safe
Select **4. Decrypt Safe** to unlock the `.safe` container and restore your files to the `safe/` folder.

---

## Contributing
Contributions are welcome! Feel free to submit a pull request or open an issue to improve the app.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

## Disclaimer
This tool is provided as-is. Use it at your own risk. The authors are not responsible for any data loss or security breaches caused by improper usage of this tool.

---

Happy Encrypting! 😊


