import base64
from tkinter import Tk, filedialog
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# 🪟 Hide the root window for file selection
root = Tk()
root.withdraw()

# -------------------- USER CHOICE --------------------
print("🔐 What do you want to do?")
print("1. Encrypt a file")
print("2. Decrypt a file")
choice = input("Enter 1 or 2: ").strip()

# =================== ENCRYPTION =====================
if choice == "1":
    print("📂 Select your PUBLIC key (PEM format) for encryption:")
    public_key_path = filedialog.askopenfilename(title="Select Public Key")
    if not public_key_path:
        print("❌ No public key selected. Exiting.")
        exit()

    print("\n📂 Select the file you want to encrypt:")
    file_to_encrypt = filedialog.askopenfilename(title="Select File to Encrypt")
    if not file_to_encrypt:
        print("❌ No file selected. Exiting.")
        exit()

    # Load public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Read file content
    with open(file_to_encrypt, "rb") as f:
        file_content = f.read()

    # Encrypt it
    ciphertext = public_key.encrypt(
        file_content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save as base64
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    encrypted_file_path = file_to_encrypt + ".enc"
    with open(encrypted_file_path, "w") as f:
        f.write(ciphertext_base64)

    print(f"✅ Encrypted file saved as: {encrypted_file_path}")

# =================== DECRYPTION =====================
elif choice == "2":
    print("📂 Select your PRIVATE key (PEM format) for decryption:")
    private_key_path = filedialog.askopenfilename(title="Select Private Key")
    if not private_key_path:
        print("❌ No private key selected. Exiting.")
        exit()

    print("\n📂 Select the encrypted file to decrypt (base64 format):")
    encrypted_file_path = filedialog.askopenfilename(title="Select Encrypted File")
    if not encrypted_file_path:
        print("❌ No encrypted file selected. Exiting.")
        exit()

    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Read and decode ciphertext
    with open(encrypted_file_path, "r", encoding='utf-8', errors='ignore') as f:
        encrypted_message = f.read()
    ciphertext = base64.b64decode(encrypted_message)

    # Decrypt
    try:
        decrypted_message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        decrypted_file_path = encrypted_file_path + ".dec"
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_message)

        print(f"✅ Decrypted file saved as: {decrypted_file_path}")

    except Exception as e:
        print("❌ Decryption failed.")
        print("Reason:", str(e))

# =================== INVALID =====================
else:
    print("🤨 Invalid choice. Please enter 1 or 2 next time.")
