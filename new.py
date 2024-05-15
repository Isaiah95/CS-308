import argparse
import os
import pyaes


def main():
    help_screen = '''Type 'exit' to exit, 'e' to encrypt a message, or 'd' to decrypt a message'''
    parser = argparse.ArgumentParser(description=help_screen, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-e', '--encrypt', help="Type a message you want to encrypt", type=str)
    parser.add_argument('-d', '--decrypt', help="Enter the token you want to decrypt", type=str)
    parser.add_argument('--mode', help="Encryption mode: aes-cbc or aes-ctr", choices=['aes-cbc', 'aes-ctr'], default='aes-cbc')
    args = parser.parse_args()

    while True:
        ans = input("Type 'exit' to exit, 'e' to encrypt a message, or 'd' to decrypt a message: ")
        
        if ans.lower() == "exit":
            break

        if ans.lower() == "e":
            if args.encrypt:
                message = args.encrypt
            else:
                message = input("Enter the message to encrypt: ")

            key = os.urandom(16)  # Generate a random 16-byte key
            iv = os.urandom(16)   # Generate a random 16-byte IV
            if args.mode == 'aes-cbc':
                aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
            else:
                aes = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(iv))

            ciphertext = aes.encrypt(message)

            print("Encrypted message:", ciphertext.hex())

        elif ans.lower() == "d":
            if args.decrypt:
                ciphertext = bytes.fromhex(args.decrypt)
            else:
                ciphertext_hex = input("Enter the ciphertext to decrypt (in hexadecimal): ")
                ciphertext = bytes.fromhex(ciphertext_hex)

            key = input("Enter the key: ").encode()
            iv = input("Enter the IV: ").encode() if args.mode == 'aes-cbc' else b''  # IV is not needed for CTR mode
            if args.mode == 'aes-cbc':
                aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
            else:
                aes = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(iv))

            decrypted = aes.decrypt(ciphertext)

            print("Decrypted message:", decrypted.decode())

if __name__ == '__main__':
    main()

