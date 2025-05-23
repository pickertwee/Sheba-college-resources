# 🔐 Cryptography Tasks using OpenSSL

## 📑 Table of Contents
- [🔐 Cryptography Tasks using OpenSSL](#-cryptography-tasks-using-openssl)
  - [📑 Table of Contents](#-table-of-contents)
  - [🛡️ Task 1: Symmetric Encryption using AES](#️-task-1-symmetric-encryption-using-aes)
  - [🔑 Task 2: Asymmetric Encryption using RSA](#-task-2-asymmetric-encryption-using-rsa)
  - [🔁 Task 3: Hashing and Message Integrity (SHA-256)](#-task-3-hashing-and-message-integrity-sha-256)
    - [Why the hashes change after a bit of modification???](#why-the-hashes-change-after-a-bit-of-modification)
  - [📝 Task 4: Digital Signatures using RSA](#-task-4-digital-signatures-using-rsa)
    - [Why the verification fails after a bit of changes???](#why-the-verification-fails-after-a-bit-of-changes)



## 🛡️ Task 1: Symmetric Encryption using AES
Here we will encrypt and decrypt a file using AES-256.

1. First, create a sample text file
   ```sh
   echo "This is a secret text." > sheba.txt
   ```
   ![sheba file](Screenshots/sheba.txt.png)
   ![sheba-content](Screenshots/sheba-content.png)

2. Next, we encrypt the file using AES-256-CBC
   ```sh
   openssl enc -aes-256-cbc -salt -in sheba.txt -out sheba.enc
   ```
   ![sheba-enc](Screenshots/sheba-enc.png)
   -  After running the command, you are required to insert any password for the encryption.
      | **Option**     | **Explanation**                                                          |
      | -------------- | ------------------------------------------------------------------------ |
      | openssl        | Call the openssl tools                                                   |
      | enc            | stands for 'encrypt' - symmetric encryption                              |
      | -aes-256-cbc   | Choosing AES cipher with 256-bit key in CBC (Cipher Block Chaining) mode |
      | -salt          | Add random 8-byte salt                                                   |
      | -in sheba.txt  | Specifies the input plaintext file                                       |
      | -out sheba.enc | Specifies the output encrypted file                                      |
   
   ![sheba-enc2](Screenshots/sheba-enc(2).png)
   - As you can see the plaintext before this has been encrypted. You can't even read it nor understand.

3. In order to decrypt the text, we need to use this command.
   ```sh
   openssl enc -d -aes-256-cbc -in sheba.enc -out sheba-decrypted.txt
   ```
   ![sheba-dec](Screenshots/sheba-dec.png)
   - Decryption need the password. Insert the password that you has setup.
      | **Option** | **Explaination** |
      | ---------- | ---------------- |
      | openssl    | Call the openssl |
      | enc        | specifies encryption       |


   ![sheba-dec](Screenshots/sheba-dec(2).png)
   - Tadaaaa!!! We successfully encrypt the fileee.

----
## 🔑 Task 2: Asymmetric Encryption using RSA
Here we will generate an RSA key pair, encrypt a message with the public key, and decrypt it with the private key.

1. You need to generate an RSA private key (2048-bit)
   ```sh
   openssl genrsa -out private_key.pem 2048
   ```
   ![rsa-privatekey-generate](Screenshots/rsa-privkey.png)
   ![rsa-privatekey](Screenshots/privkey.png)

2. Extract the public key from the private key that we just generate. 
   ```sh
   openssl rsa -in private_key.pem -pubout -out public_key.pem
   ```
   ![rsa-publickey-generate](Screenshots/rsa-pubkey.png)
   ![rsa-publickey](Screenshots/pubkey.png)

   Below is the different between the private key and public key that has been generated.
   ![rsa-diff-key](Screenshots/pubpriv-diff.png)

3. Create or take any of your secret file. Encrypt the file using the Public key that we just extracted.
   ```sh
   openssl pkeyutl -encrypt -inkey public_key.pem -pubin -in shebarsa.txt -out shebarsa.txt.enc
   ```
   ![rsa-pkeyutl](Screenshots/rsa-pkeyutl.png)
   > using `pkeyutl` because it is much more flexible, modern and supports more crypto operations. 

   if using 
   ```sh
   openssl rsautl -encrypt -inkey public_key.pem -pubin -in shebarsa.txt -out shebarsa.txt.enc
   ```
   it will show the output: 
   ![rsa-rsautl](Screenshots/rsa-rsautl.png)
   ```sh
   The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead.
   ```
   That is why we will be using **pkeyutl** instead rsautl. 
   The output of encypted file:
   ![rsa-enc-output](Screenshots/rsa-sheba.txt.png)

4. Lets decrypt the file so it is readable.
   ```sh
   openssl pkeyutl -decrypt -inkey private_key.pem -in shebarsa.txt.enc -out decrypted.txt
   ```
   ![rsa-decrypt](Screenshots/rsa-dec.png)

   The output of decrypted file.
   ![rsa-dec-output](Screenshots/rsa-dec.txt.png)

5. The diff of encrypted file and decrypted filee.
   ![rsa-diff](Screenshots/rsa-diff.png)

   ---
   Above are the steps on how to encrypt and decrypt the file you create by yourself using asymmetric key. What if we try to decrypt someone else file using our own private key??

   1. Below here I already got my friend encrypted file. She encrypted her file using my public key.
      ![seri-rsa-enc](Screenshots/seri-rsa-enc.png)
   2. Now, I will be decrypt the file using my own private key.
      ![seri-rsa-dec](Screenshots/seri-rsa-dec.png)
   3. The output:
      ![seri-rsa-dec2](Screenshots/seri-rsa-dec2.png)
      

----
## 🔁 Task 3: Hashing and Message Integrity (SHA-256)

1. It just the same like before, prepare a file or docs that you want to encrypt but this time we will be using hashing. 
   ![hash-txt](Screenshots/hash.txt.png)
   ![hash-txt](Screenshots/hash-before.png)

2. Here we will start hashing the file that has been created.
   ```sh
   openssl dgst -sha256 sheba-hash.txt
   ```
   ![hash-enc](Screenshots/hashed-hash.txt.png)

3. Lets edit the file and hash it again. 
   ```sh
   vim sheba-hash.txt
   ```
   In the text file `sheba-hash.txt`, I add some sentences like below.
   ![hash-aft](Screenshots/hash-add-sentence.png)
   
   After edit the file and hash it again, the hash will be different.
   ![hash-enc](Screenshots/hashed-hash.txt.png)
   ![hash-enc(2)](Screenshots/hashed-hash.txt2.png)
   Take a closer look on it, it looks different. This proof that the integrity of the file has been **compromised**. 
   ### Why the hashes change after a bit of modification???
   - The hashes change because the function takes the input data and applies a series of mathematical operations to it.
   - The hash function ensures that even a small change in the file or data, it will produces a significantly different hash value.

4. There are alternative tools beside the command we use before. 
   ```sh
   sha256sum sheba-hash.txt
   ```
   ![hash-diff](Screenshots/hash-sha256.png)
   The output is still the same, it just the command that is different. 

-----
## 📝 Task 4: Digital Signatures using RSA

Here we will be making digital signatures using RSA.

1. We need to create the file that are needed. 
   ```sh
   vim sheba-agreement.txt
   ```
   ![dg-agreement.txt](Screenshots/dg-before.png)
2. Now, we will sign the file using the private key that we already created before int task 2.
   ```sh
   openssl dgst -sha256 -sign private_key.pem -out agreement.sig sheba-agreement.txt
   ```
   ![dg-agreement-enc](Screenshots/dg-priv.png)
   ![dg-agreement-enc](Screenshots/dg-enc.png)
   >agreement.sig = the digital signature file

3. Next we try to verify the signature using the public key.
   ```sh
   openssl dgst -sha256 -verify public_key.pem -signature agreement.sig sheba-agreement.txt
   ```
   ![dg-agreement-verify](Screenshots/dg-verify.png)
   if it's legit, you will get:
   ```sh
   Verified OK
   ```
4. Here we just want to check, what will happen if we modify the file?? 
   Below are the original file:
   ![dg-orig-file](Screenshots/dg-text-bfr.png)
   and here I modify the file:
   ![dg-modify-file](Screenshots/dg-text-aft.png)
   save the file, and lets see what will happen if we want to verify the digital signature that has been made before.
   ![dg-verify-modifile](Screenshots/dg-verify2.png)
   The output show `Verification failure`.

   ### Why the verification fails after a bit of changes???
   - The reason verification fails is because the original file was digitally signed using the private key.
   - But after the file was modified, that new version was never signed with the private key.
   So when we try to verify the modified file using the original signature, it doesn’t match — and the verification fails.

