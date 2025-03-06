from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib
import json

def decryption(username: str, password: str, hashAlgorithm: str):
    # Attempts to load the encryption data for the given user
    try:
        with open(f'{username}_encryption.json', 'r', encoding='utf-8') as file:
            encryptionInfo = json.load(file)
    except FileNotFoundError: # If a user doesn't have an encrypted message, the file will not exist
        print("Could not find a message with that username. Aborting")
    except:
        print("An unexpected error occurred. Aborting")
        exit(0)
        
        
    # Convert stored hash and message back to bytes
    encryptionInfo["IV"] = long_to_bytes(encryptionInfo["IV"])
    encryptionInfo["Encrypted message"] = long_to_bytes(encryptionInfo["Encrypted message"])
    
    # Compare saved message to saved hash
    if hashAlgorithm == 'sha256':
        storedHash = hashlib.sha256(encryptionInfo['Encrypted message']).hexdigest()
    elif hashAlgorithm == 'md5':
        storedHash = hashlib.md5(encryptionInfo['Encrypted message']).hexdigest()
    
    if storedHash != encryptionInfo["Hash"]:
        print("Message has been altered. Cannot safely decrypt. Aborting")
        exit(0)
    else:
        print("Encrypted message verified. Decrypting...")
        
    # Create the decryption key
    if hashAlgorithm == 'sha256':
        key = hashlib.sha256(password.encode()).digest()
    elif hashAlgorithm == 'md5':
        key = hashlib.md5(password.encode()).digest()
    
    # Decrypt the saved message and remove padding
    encryptionAlgorithm = AES.new(key, AES.MODE_CBC, iv = encryptionInfo["IV"])
    plaintext = encryptionAlgorithm.decrypt(encryptionInfo['Encrypted message'])
    plaintext = unpad(plaintext, 16).decode()
    print(f"Decrypted message: {plaintext}")
    
    

def encryption(username: str, password: str, hashAlgorithm: str):
    # Accept the message the user wants to encrypt then pad the given message to be a multiple of 16
    message =  input("Enter the message you want to encrypt: ").encode()
    message = pad(message, 16)
    
    # Create the encryption key
    if hashAlgorithm == 'sha256':
        key = hashlib.sha256(password.encode()).digest()
    elif hashAlgorithm == 'md5':
        key = hashlib.md5(password.encode()).digest()
    
    # Create the encryption algorithm object in CBC mode with the hash key and a random 16 byte IV
    iv = get_random_bytes(16)
    encryptionAlgorithm = AES.new(key, AES.MODE_CBC, iv = iv)
    
    # Encrypt the padded messgae
    cipherText = encryptionAlgorithm.encrypt(message)
    
    # Create a hash of the encrypted message
    if hashAlgorithm == 'sha256':
        messageHash = hashlib.sha256(cipherText).hexdigest()
    elif hashAlgorithm == 'md5':
        messageHash = hashlib.md5(cipherText).hexdigest()
    
    # Write the IV, the encrypted message, and the message hash in a JSON file
    encryptionInfo = {
        "IV": bytes_to_long(iv), # JSON doesn't allow storing bytes, converted to long for storage
        "Encrypted message": bytes_to_long(cipherText), 
        "Hash": messageHash
        }
    
    try:
        # The following was taken from stackoverflow: https://stackoverflow.com/questions/12309269/how-do-i-write-json-data-to-a-file
        with open(f'{username}_encryption.json', 'w', encoding='utf-8') as file:
            json.dump(encryptionInfo, file, ensure_ascii=False, indent=4)
        
        print("Encrypted message successfully saved")
    except:
        print("An error occured saving the encrypted message. Aborting")
    
    
    

def main():
    action = input("Would you like to Encrypt(E) or Decrypt(D): ")

    if action != 'E' and action != 'D':
        print("Unknown action. Aborting")
        exit(0)
    
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    match input("User SHA-256(Y) or MD5(N): "):
        case 'Y':
            hashAlgorithm = 'sha256'
        case 'N':
            hashAlgorithm = 'md5'
        case _:
            print("Unknown hash algorithm. Aborting")
            exit(0)
    
    match action:
        case 'E':
            encryption(username, password, hashAlgorithm)
        case 'D':
            decryption(username, password, hashAlgorithm)


if __name__ == "__main__":
    main()