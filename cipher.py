import argparse
import os
import pyaes

def pad(text):
    """
    Pad the input text to be a multiple of 16 bytes using PKCS#7 padding.
    """
    padding_length = 16 - (len(text) % 16)
    return text + bytes([padding_length] * padding_length)

def unpad(text):
    """
    Remove PKCS#7 padding from the input text.
    """
    padding_length = text[-1]
    return text[:-padding_length]

def pad_iv(iv):
    """
    Pad or truncate the initialization vector (IV) to be 16 bytes long.
    """
    if len(iv) > 16:
        return iv[:16]
    elif len(iv) < 16:
        padding_length = 16 - len(iv)
        return iv + bytes([padding_length] * padding_length)
    else:
        return iv

def read_file(file_path):
    """
    Read the contents of a file.
    """
    with open(file_path, 'rb') as file:
        return file.read()

def write_file(file_path, data):
    """
    Write data to a file.
    """
    with open(file_path, 'wb') as file:
        file.write(data)

def main():
    help_screen = '''pass --encrypt=<encrypts_your_message> --decrypt=<decrypts_your_message> --mode=<encryption_mode> '''
    parser = argparse.ArgumentParser(description=help_screen, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-e', '--encrypt', help="Type a message you want to encrypt or provide a path to a text file", type=str)
    parser.add_argument('-d', '--decrypt', help="Enter the token you want to decrypt or provide a path to a text file", type=str)
    parser.add_argument('--mode', help="Encryption mode: aes-cbc or aes-ctr", choices=['aes-cbc', 'aes-ctr'], default='aes-cbc')
    parser.add_argument('--key', help="Enter the encryption key (required for both encryption and decryption)", type=str)
    parser.add_argument('--iv', help="Enter the initialization vector (IV) if using AES-CBC mode", type=str)
    parser.add_argument('--output', help="Specify the output file path", default="output.txt")
    args = parser.parse_args()

    while True:
        ans = input("Type 'exit' to exit, 'e' to encrypt a message, or 'd' to decrypt a message: ")
        
        if ans.lower() == "exit":
            break

        if ans.lower() == "e":
            if args.encrypt and os.path.exists(args.encrypt):
                message = read_file(args.encrypt)
            else:
                file_path = input("Enter the path to the text file you want to encrypt: ")
                if os.path.exists(file_path):
                    message = read_file(file_path)
                else:
                    print("File not found.")
                    continue

            # Pad the message
            padded_message = pad(message)

            if args.mode == 'aes-cbc':
                key = input("Enter the encryption key: ").encode()
                iv = input("Enter the initialization vector (IV): ").encode()
                iv = pad_iv(iv)
                aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
            else:
                key = input("Enter the encryption key: ").encode()
                aes = pyaes.AESModeOfOperationCTR(key)
            
            ciphertext = b''  # Initialize the ciphertext as a byte string
            
            for i in range(0, len(padded_message), 16):
                block = padded_message[i:i+16]
                encrypted_block = aes.encrypt(block)
                ciphertext += encrypted_block

            # Write encrypted message to a new file
            write_file(args.output, ciphertext)

            print(f"Encrypted message written to {args.output}")

        elif ans.lower() == "d":
            if args.decrypt and os.path.exists(args.decrypt):
                ciphertext = read_file(args.decrypt)
            else:
                file_path = input("Enter the path to the text file you want to decrypt: ")
                if os.path.exists(file_path):
                    ciphertext = read_file(file_path)
                else:
                    print("File not found.")
                    continue

            key = input("Enter the encryption key: ").encode()
            if args.mode == 'aes-cbc':
                iv = input("Enter the initialization vector (IV): ").encode()
                iv = pad_iv(iv)
                aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
            else:
                aes = pyaes.AESModeOfOperationCTR(key)

            decrypted_message = b''  # Initialize the decrypted message as a byte string
            
            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i+16]
                decrypted_block = aes.decrypt(block)
                decrypted_message += decrypted_block

            decrypted_message = unpad(decrypted_message)

            # Write decrypted message to a new file
            write_file(args.output, decrypted_message)

            print(f"Decrypted message written to {args.output}")

if __name__ == '__main__':
    main()
