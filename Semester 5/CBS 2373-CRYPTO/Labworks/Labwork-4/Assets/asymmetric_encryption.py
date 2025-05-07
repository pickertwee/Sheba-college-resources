from cryptography.hazmat.primitives.asymmetric import rsa #import rsa to generate asymmetric keys
from cryptography.hazmat.primitives import serialization #convert the keys to PEM format .pem .pub
import os

dir_path = r"RSA-key"
os.makedirs(dir_path, exist_ok=True)


#Generate RSA private key 
private_key = rsa.generate_private_key( 
    public_exponent=65537, 
    key_size=2048 
)

#place for your password
private_key_pass = b"your-password" #b means byte object -- your-password basically just a placeholder, can put anything

#encrypt the private key 
encrypted_pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM, #PEM = base64 with headers (----BEGIN PRIVATE KEY----)
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
)

#Generate RSA public key from private key
pem_public_key = private_key.public_key().public_bytes(  
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo 
)

#save private key
with open(os.path.join(dir_path, "example-rsa.pem"), "w") as private_key_file:
    private_key_file.write(encrypted_pem_private_key.decode())

#save public key
with open(os.path.join(dir_path, "example-rsa.pub"), "w") as public_key_file:
    public_key_file.write(pem_public_key.decode())
