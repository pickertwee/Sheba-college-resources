from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Original data
data = b'Cryptography Lab by Sheba, NWS23010003'

# Generate key & cipher
key = get_random_bytes(16)  # AES-128
cipher = AES.new(key, AES.MODE_EAX)

# Encrypt
ciphertext, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce

print("Ciphertext:", ciphertext)
print("Tag:", tag)
print("Nonce:", nonce)

# --------------------------
# Decryption phase
# --------------------------

# Recreate the cipher for decryption
cipher_dec = AES.new(key, AES.MODE_EAX, nonce=nonce)

# Decrypt and verify
try:
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
    print("Decrypted:", decrypted.decode())
except ValueError:
    print("Decryption failed or data tampered!")
