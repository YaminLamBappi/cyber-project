from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt_file(input_file, output_file):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file, 'wb') as f:
        f.write(ciphertext)

    print(f"Encryption Key: {key.hex()}")  # Print the key
    return key  # Return the key for later use


def decrypt_file(input_file, output_file, key=None):
    if key is None:
        key = bytes.fromhex(input("Enter the decryption key in hexadecimal format: "))

    cipher = AES.new(key, AES.MODE_CBC)

    try:
        with open(input_file, 'rb') as f:
            ciphertext = f.read()

        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        print("Decryption completed.")
    except Exception as e:
        print(f"Error during decryption: {e}")


def main():
    while True:
        input_file = input("Enter the path to the input file: ")
        output_file = input("Enter the path for the output file: ")

        operation = input("Do you want to encrypt or decrypt? (e/d/q to quit): ").lower()

        if operation == 'e':
            key = encrypt_file(input_file, output_file)
            print("Encryption completed.")
        elif operation == 'd':
            key = bytes.fromhex(input("Enter the decryption key in hexadecimal format: "))
            decrypt_file(input_file, output_file, key)
            print("Decryption completed.")
        elif operation == 'q':
            print("Exiting the program.")
            break  # Exit the loop and end the program
        else:
            print("Invalid operation. Please choose 'e' for encryption, 'd' for decryption, or 'q' to quit.")


if __name__ == "__main__":
    main()
