from libnum import generate_prime
from math import gcd
from zlib import compress, decompress
from base64 import b64encode, b64decode
from os import system


def encrypt(public_key: int, product_of_prime_numbers: int) -> str:
    """Encrypting the user message using RSA Encryption

    Args:
        public_key (int): a public key (e) used to encrypt
        the message
        product_of_prime_numbers (int): product of randomly
        generated prime numbers (n)

    Returns:
        cipher_text (str): returns the cipher text of the message
    """
    message = verify_decrypted_message()
    ascii_message = [ord(char) for char in message]
    cipher_text_bytes = b"".join(
        [
            pow(ascii_number, public_key, product_of_prime_numbers).to_bytes(
                64, byteorder="big"
            )
            for ascii_number in ascii_message
        ]
    )
    compressed_cipher_text = compress(cipher_text_bytes)
    cipher_text = b64encode(compressed_cipher_text).decode("utf-8")
    return cipher_text


def decrypt(private_key: int, product_of_prime_numbers: int) -> str:
    """Decrypting the encrypted message using RSA Encryption

    Args:
        private_key (int): a private key (d) used to decrypt
        the message
        product_of_prime_numbers (int): product of randomly
        generated prime numbers (n)

    Returns:
        decrypted_message (str): returns the decrypted text of the message
    """
    message = input("\nInput your encrypted message: ")
    decoded_message = b64decode(message.encode("utf-8"))
    decompressed_data = decompress(decoded_message)
    blocks_list = [
        decompressed_data[i : i + 64] for i in range(0, len(decompressed_data), 64)
    ]
    ascii_message_list = [
        int.from_bytes(block, byteorder="big") for block in blocks_list
    ]
    decrypted_message = "".join(
        chr(pow(ascii_number, private_key, product_of_prime_numbers))
        for ascii_number in ascii_message_list
    )
    return decrypted_message


def verify_decrypted_message() -> str:
    """Verifying the user input for encrypting a message

    Returns:
        message (str): returns the users message,
        if it is checked correctly
    """
    while True:
        message = input("\nInput your decrypted message: ")
        if len(message) <= 128:
            return message
        else:
            system("cls")
            print("The decrypted message must have a maximum of 128 characters!")
            input("\nPress the Enter key to insert a new message. . .")
            system("cls")
            print("ENCRYPTING A MESSAGE")


def verify_encrypt_inputs() -> int:
    """Validating the user input for the encryption keys

    Returns:
        e (int), n (int): returns the public keys
    """
    while True:
        n = input("\nInput the product of prime numbers (n): ")
        if n.isnumeric():
            while True:
                e = input("\nInput the public key (e): ")
                if e.isnumeric():
                    return int(e), int(n)
                else:
                    system("cls")
                    print("Invalid public key (e)")
                    input("\nPress the Enter key to insert a new public key. . .")
                    system("cls")
                    print("ENCRYPTING A MESSAGE")
        else:
            system("cls")
            print("Invalid product of prime numbers (n)")
            input("\nPress the Enter key to insert a new product of prime numbers. . .")
            system("cls")
            print("ENCRYPTING A MESSAGE")


def verify_decrypt_inputs() -> int:
    """Validating the user input for the decryption keys

    Returns:
        d (int), n (int): returns the private keys
    """
    while True:
        n = input("\nInput the product of prime numbers (n): ")
        if n.isnumeric():
            while True:
                d = input("\nInput the private key (d): ")
                if d.isnumeric():
                    return int(d), int(n)
                else:
                    system("cls")
                    print("Invalid private key (d)")
                    input("\nPress the Enter key to insert a new private key. . .")
                    system("cls")
                    print("DECRYPTING A MESSAGE")
        else:
            system("cls")
            print("Invalid product of prime numbers (n)")
            input("\nPress the Enter key to insert a new product of prime numbers. . .")
            system("cls")
            print("DECRYPTING A MESSAGE")


def generate_prime_numbers() -> int:
    """Generating random prime numbers with 256 bits (2⁸ bits)

    Returns:
        prime_number_one (int), prime_number_two (int):
        returns two randomly generated prime numbers
    """
    while True:
        prime_number_one = generate_prime(256)
        prime_number_two = generate_prime(256)
        if prime_number_one != prime_number_two:
            break
    return prime_number_one, prime_number_two


def generate_n_and_phi_of_n(prime_number_one: int, prime_number_two: int) -> int:
    """Generating the product of prime numbers and the
    phi of them used in the RSA Encryption

    Args:
        prime_number_one (int): a first prime number
        prime_number_two (int): a second prime number,
        different from the first

    Returns:
        n (int), phi_of_n (int): returns both the product of
        prime numbers and the phi of them
    """
    n = prime_number_one * prime_number_two
    phi_of_n = (prime_number_one - 1) * (prime_number_two - 1)
    return n, phi_of_n


def generate_public_key(phi_of_n: int) -> int:
    """Generating the public key (e) using
    the Fernet prime 65537

    Args:
        phi_of_n (int): phi of the product of prime numbers | Φ(n)

    Returns:
        public_key (int): returns the public key (e)
    """
    for i in range(65537, phi_of_n):
        if phi_of_n % i != 0:
            if gcd(phi_of_n, i) == 1:
                public_key = i
                return public_key


def generate_private_key(public_key: int, phi_of_n: int) -> int:
    """Generating the private key (d) using the
    modular inverse algorithm

    Args:
        public_key (int): a public key (e)
        phi_of_n (int): phi of the product of prime numbers | Φ(n)

    Returns:
        private_key (int): returns the private key (d)
    """
    private_key = pow(public_key, -1, phi_of_n)
    return private_key


def menu():
    """Creating a interactive menu for the users
    """
    while True:
        system("cls")
        print("RSA ENCRYPTION AND DECRYPTION\n")
        print("Choose an option: ")
        print("[1] Generate new keys")
        print("[2] Encrypt a message with existing key")
        print("[3] Decrypt a message with existing key")
        print("[0] Exit")

        option = input("\nInsert the option here: ")

        match option:
            case "1":
                system("cls")
                print("GENERATE NEW KEY VALUES")
                p, q = generate_prime_numbers()
                n, m = generate_n_and_phi_of_n(p, q)
                e = generate_public_key(m)
                d = generate_private_key(e, m)

                print(f"\nThe product of prime numbers (n): {n}")
                print(f"\nYour new public key (e): {e}")
                print(f"\nYour new private key (d): {d}")

                input("\nPress the Enter key to continue. . .")

            case "2":
                system("cls")
                print("ENCRYPTING A MESSAGE")
                e, n = verify_encrypt_inputs()

                cipher_text = encrypt(e, n)
                print(f"\nHere is your encrypted text:\n{cipher_text}")

                input("\nPress the Enter key to continue. . .")

            case "3":
                system("cls")
                print("DECRYPTING A MESSAGE")
                d, n = verify_decrypt_inputs()

                decrypted_message = decrypt(d, n)
                print(f"\nHere is your decrypted message:\n{decrypted_message}")

                input("\nPress the Enter key to continue. . .")

            case "0":
                system("cls")
                print("Exiting the program!")
                print("Thanks you for using our technology. Goodbye!")
                input("\nPress the Enter key to continue. . .")
                system("cls")
                break

            case _:
                system("cls")
                print("Invalid option. Please select a valid option!")
                input("\nPress the Enter key to continue. . .")


def main():
    """Executes when the file is directly
    executed and starts running
    """
    menu()


if __name__ == "__main__":
    main()
