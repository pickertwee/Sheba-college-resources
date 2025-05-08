from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from tkinter import Tk, filedialog
import os

# Hide Tkinter root window
root = Tk()
root.withdraw()

# --------- FILE PICKING ---------
print("📂 Select the PRIVATE key (PEM format):")
private_key_path = filedialog.askopenfilename(title="Select Private Key")
print(f"🔐 Private key selected: {private_key_path}")

print("\n📂 Select the PUBLIC key (PEM format):")
public_key_path = filedialog.askopenfilename(title="Select Public Key")
print(f"🔓 Public key selected: {public_key_path}")

print("\n📄 Select the file to SIGN & VERIFY:")
message_path = filedialog.askopenfilename(title="Select File")
print(f"📝 File selected: {message_path}")

# --------- LOAD KEYS ---------
with open(private_key_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open(public_key_path, "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# --------- SIGN ONLY IF NOT YET SIGNED ---------
signature_path = message_path + ".sig"

if not os.path.exists(signature_path):
    print("\n✍️ Signing the file for the first time...")
    with open(message_path, "rb") as f:
        message = f.read()

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(signature_path, "wb") as f:
        f.write(signature)

    print(f"✅ Signature created and saved as: {signature_path}")
else:
    print(f"ℹ️ Signature already exists: {signature_path} — skipping signing")

# --------- VERIFYING ---------
print("\n🔎 Verifying the file against the signature...")

try:
    with open(message_path, "rb") as f:
        message = f.read()
    with open(signature_path, "rb") as f:
        signature = f.read()

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\n✅ Signature is VALID. File is clean.")
except Exception as e:
    print("\n❌ Signature verification FAILED.")
  
