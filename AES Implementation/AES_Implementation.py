from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib
import json

def Encryption(username: str, password: str, hashAlgorithm):
    # Accept the message the user wants to encrypt then pad the given message to be a multiple of 16
    message =  input("Enter the message you want to encrypt: ").encode()
    message = pad(message, 16)
    
    # Create the encryption key
    hashAlgorithm.update(password.encode())
    
    # Create the encryption algorithm object in CBC mode with the hash key and a random IV
    key = hashAlgorithm.digest()
    iv = get_random_bytes(16)
    encryptionAlgorithm = AES.new(key, AES.MODE_CBC, iv = iv)
    
    # Encrypt the padded messgae
    cipherText = encryptionAlgorithm.encrypt(message)
    
    # Create a hash of the encrypted message
    hashAlgorithm.update(cipherText)
    messageHash = hashAlgorithm.hexdigest()
    
    # Write the IV, the encrypted message, and the message hash in a JSON file
    encryptionInfo = {
        "IV": bytes_to_long(iv), 
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
            hashAlgorithm = hashlib.sha256()
        case 'N':
            hashAlgorithm = hashlib.md5()
        case _:
            print("Unknown hash algorithm. Aborting")
            exit(0)
    
    match action:
        case 'E':
            Encryption(username, password, hashAlgorithm)


if __name__ == "__main__":
    main()