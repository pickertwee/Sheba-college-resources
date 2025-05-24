from Crypto.Cipher import AES
    import os
    from hashlib import sha256

    KEY_SUFFIX = "RahsiaLagi"
    KEY_STR = f"Bukan{KEY_SUFFIX}"
    KEY = sha256(KEY_STR.encode()).digest()[:16]  # same  key as encryption

    def unpad(data):
        pad_len = data[-1]
        return data[:-pad_len]

    def decrypt_file(enc_filepath, output_folder):
        with open(enc_filepath, "rb") as f:
            ciphertext = f.read()
        cipher = AES.new(KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted)

        filename = os.path.basename(enc_filepath[:-4])  # remove .enc
        output_path = os.path.join(output_folder, filename)
        with open(output_path, "wb") as f:
            f.write(plaintext)

    if __name__ == "__main__":
        input_folder = "locked_files/"
        output_folder = "unlocked_files/"

        os.makedirs(output_folder, exist_ok=True)

        encrypted_files = [f for f in os.listdir(input_folder) if f.endswith(".enc")]

        for filename in encrypted_files:
            input_path = os.path.join(input_folder, filename)
            decrypt_file(input_path, output_folder)
            print(f"Decrypted: {filename} → {output_folder}")