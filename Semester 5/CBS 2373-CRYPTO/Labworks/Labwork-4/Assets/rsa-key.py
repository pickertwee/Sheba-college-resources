from cryptography.hazmat.primitives.asymmetric import rsa #generate asymmetric keys
from cryptography.hazmat.primitives import serialization #convert keys into savable formats
import os #for file handling

# Define your directories
public_key_dir = "RSA-key"  # Relative, stays in your project
private_key_path = r"C:\Users\sheba\OneDrive\Desktop\vscode\Haise's Workspace\sheba_private_key.pem"  
# Make sure RSA-key folder exists for public key
os.makedirs(public_key_dir, exist_ok=True) #if the folders does exist, make it. else, just chill

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537, 
    key_size=2048 
)

# Serialize keys
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM, #make in PEM(Privacy-Enhanced Email) format 
    format=serialization.PrivateFormat.PKCS8, #PKCS8 = modern format for private keys
    encryption_algorithm=serialization.NoEncryption()
)

pem_public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Write public key to project directory
with open(os.path.join(public_key_dir, "sheba_public_key.pem"), "wb") as f:
    f.write(pem_public_key)

# Write private key OUTSIDE project folder
with open(private_key_path, "wb") as f:
    f.write(pem_private_key)

