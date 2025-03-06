from Crypto.Cipher import AES
from os import urandom
import hashlib

def Encryption(username: str, password: str, hashAlgorithm):
    message =  input("Enter the message you want to encrypt: ").encode()
    hashAlgorithm.update(password.encode())
    key = hashAlgorithm.digest()
    iv = urandom(16)
    encryptionAlgorithm = AES.new(key, AES.MODE_CBC, iv = iv)
    
    

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