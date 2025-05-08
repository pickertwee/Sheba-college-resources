from Crypto.Cipher import AES #generate AES
from Crypto.Random import get_random_bytes #get random value (keys)

# Original data
data = b'Cryptography Lab by Sheba, NWS23010003'

# Generate key & cipher (AES-128)
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)

# Encrypt
ciphertext, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce  # Save nonce for decryption

# Show ciphertext in hex
print("🔐 Ciphertext (hex):", ciphertext.hex())

# Decryption phase
# Recreate the cipher for decryption
cipher_dec = AES.new(key, AES.MODE_EAX, nonce=nonce)

# Decrypt and verify
try:
    decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
    print("🔓 Decrypted:", decrypted.decode())
except ValueError:
    print("❌ Decryption failed or data tampered!")
