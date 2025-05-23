# Lab 2: Cryptographic Attacks: Cracking Weak Password Hashes and Exploiting Poor Authentication in Databases

## 🔐 **Objective**
    1. Identify and exploit cryptographic weaknesses in database authentication and password storage.
    2. Perform offline hash cracking after discovering password hashes in a vulnerable database.
    3. Investigate real-world cryptographic failures and propose secure solutions.
    4. Document findings clearly in GitHub (Markdown) and present a short demo/debrief.

## 🛠️ **What You’ll Need**

| Tools              | Purpose                  |
|--------------------|--------------------------|
| Metasploitable 2   | Practice attacks         |
| Kali Linux         | Attacker Machine         |


## 📝 **Lab Tasks**
1. Service Enumeration and Initial Access
    - Identify the database service running on the target.
    - Attempt to connect to the database service from Kali.
    - Observe any errors during the connection attempt and investigate.

    Hint: The database service on the target is not properly secured and has known cryptographic flaws.

    ⚠️ Analyze Problems Encountered

    - Were there any issues connecting to the database?
    - How did you resolve the connection error?
    - Document the exact command used to connect, and how you verified access.

2. Enumeration of Users and Authentication Weakness
    - After gaining access, enumerate the database users.
    - Determine which users have cryptographic authentication flaws.

    Hint: Pay close attention to the password column in the user table.

    Task:

    - Identify any users with no passwords or weak access control.
    - Attempt to authenticate using these accounts from Kali.

    ⚠️ Question:
    - Is accessing a database with no password a cryptographic failure?
    - Explain how this violates secure cryptographic authentication principles.

3. Password Hash Discovery and Hash Identification
    - Investigate available databases and identify any tables containing password hashes.
    - Extract and list the hashes found.

    Hint: One database contains user credentials stored as hashes.

    - Use hash identification tools (hashid, hash-identifier) to identify the hashing algorithm used.
    - Explain how you determined the type of hash.

    ⚠️ Question:
    - What cryptographic weaknesses exist in this hashing method?

4. Offline Hash Cracking
    - Attempt to crack the extracted hashes using tools of your choice (e.g., hashcat, john).
    - Document the commands used, and which hashes were cracked.
    - Analyze the entropy and strength of cracked passwords.

5. Cryptographic Analysis and Mitigation
    - Summarize the cryptographic issues identified:
    - Authentication flaws
    - Weak password hashing
    - Transmission of data (if applicable)
    - Propose secure alternatives, such as stronger hashing algorithms (e.g., bcrypt) and encrypted communication (SSL/TLS).
    - Optional: Use Wireshark to check if any password/hash data is transmitted unencrypted.

