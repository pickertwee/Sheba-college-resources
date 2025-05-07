import hashlib 

#Create a hash object using SHA-256 
hash_object = hashlib.sha3_256()

#user insert input
input1 = input("Enter first input: ")
input2 = input("Enter second input: ")

#hash both inputs
hash1 = hashlib.sha256(input1.encode()).hexdigest()
hash2 = hashlib.sha256(input2.encode()).hexdigest()

#display the results
print("\n---SHA-256 HASHES---")
print("Input 1: ",input1)
print("Hash: ", hash1)
print("Input 2: ",input2)
print("Hash: ", hash2)

#Compare
if hash1 == hash2:
    print("\n Hashes MATCH")
else:
    print("\n Hashes NOT MATCH")