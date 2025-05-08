import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# --------------------- ENCRYPTION ---------------------

# First thing, let's load that public key I saved earlier
with open("RSA-key/public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Now, I’m gonna grab the message from my text file.
with open("Assets/message.txt", "rb") as file:
    message = file.read()  # This is the secret I want to protect

# Time to encrypt it with the public key I loaded
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(  # I’m using OAEP padding for better security
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Okay, now let’s convert this binary ciphertext to base64, so it’s readable.
ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')

# Let’s print the encrypted message in base64 format
print("✅ Here’s the encrypted message in base64 format:")
print(ciphertext_base64)

# --------------------- DECRYPTION ---------------------

# Now, let’s move on to decryption. I need the private key to get the original message back.
with open("RSA-key/private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Let me decrypt the message now using the private key
try:
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Successfully decrypted, so I’m printing the original message
    print("✅ Decrypted message:", plaintext.decode())
except Exception as e:
    # If something went wrong, let’s print out why
    print("❌ Decryption failed.")
    print("Reason:", str(e))
