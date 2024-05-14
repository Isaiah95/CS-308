import argparse
from cryptography.fernet import Fernet, MultiFernet

def main():
    help_screen = '''pass --encrypt=<encrypts_your_message> --decrypt=<decrypts_your_message> '''
    parser = argparse.ArgumentParser(description=help_screen, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-e', '--encrypt', help="Type a message you want to encrypt", type=str)
    parser.add_argument('-d', '--decrypt', help="Enter the byte you want to decrypt", type=bytes)
    args = parser.parse_args()

    key1 = Fernet.generate_key()
    key2 = Fernet.generate_key()
    f = MultiFernet([Fernet(key1), Fernet(key2)])

    while True:
        ans = input("Type 'exit' to exit, 'e' to encrypt a message, or 'd' to decrypt a message: ")
        
        if ans.lower() == "exit":
            break

        if ans.lower() == "e":
            message = args.encrypt or input("Enter the message to encrypt: ")
            byte_message = bytes(message, encoding="utf-8")
            encrypted = f.encrypt(byte_message)
            print("Encrypted message:", encrypted)

        elif ans.lower() == "d":
            token = args.decrypt or input("Enter the token to decrypt: ")
            byte_token = bytes(token, encoding="utf-8")
            decrypted = f.decrypt(byte_token)
            print("Decrypted message:", decrypted.decode("utf-8"))

if __name__ == '__main__':
    main()