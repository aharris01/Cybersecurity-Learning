import Crypto
import hashlib

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


if __name__ == "__main__":
    main()