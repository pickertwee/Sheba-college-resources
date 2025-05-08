from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Define your directories
public_key_dir = "RSA-key"  # Relative, stays in your project
private_key_path = r"C:\Users\sheba\OneDrive\Desktop\vscode\Haise's Workspace\private_key.pem"  
# Make sure RSA-key folder exists for public key
os.makedirs(public_key_dir, exist_ok=True)

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serialize keys
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Write public key to project directory
with open(os.path.join(public_key_dir, "public_key.pem"), "wb") as f:
    f.write(pem_public_key)

# Write private key OUTSIDE project folder
with open(private_key_path, "wb") as f:
    f.write(pem_private_key)

