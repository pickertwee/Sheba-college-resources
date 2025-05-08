import hashlib
from tkinter import Tk, filedialog

# Hide the root Tk window
root = Tk()
root.withdraw()

# Let the user pick two files
print("📂 Select the first file:")
file1 = filedialog.askopenfilename(title="Select the first file")
print(f"✅ First file selected: {file1}")

print("\n📂 Select the second file:")
file2 = filedialog.askopenfilename(title="Select the second file")
print(f"✅ Second file selected: {file2}")

# Function to hash a file
def hash_file(file_path):
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except FileNotFoundError:
        print("❌ File not found.")
        return None

# Hash both files
hash1 = hash_file(file1)
hash2 = hash_file(file2)

# Compare and display
if hash1 and hash2:
    print("\n---SHA-256 HASHES---")
    print(f"File 1: {file1}")
    print(f"Hash: {hash1}")
    print(f"File 2: {file2}")
    print(f"Hash: {hash2}")

    if hash1 == hash2:
        print("\n✅ Hashes MATCH")
    else:
        print("\n❌ Hashes DO NOT MATCH")
