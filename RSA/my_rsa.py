from libnum import generate_prime
from math import gcd
from zlib import compress, decompress
from base64 import b64encode, b64decode
from os import system


# encrypt func
# input <message> from the user
# encode the string to ASCII values
# encoding the ASCII message using <public_key> and <product_of_prime_numbers>
# and encode all the characters in <ascii_message> as 64-byte strings
# compress the message using <zlib> library
# encode <compressed_cipher_text> into Base64 using the <base64> library
# return <cipher_text>
def encrypt(public_key: int, product_of_prime_numbers: int) -> str:
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


# decrypt func
# input <message> from the user
# decode <message> using Base64
# decompress the <decoded_message>
# create a list of blocks containing 64 bytes
# these 64 bytes were used to encode the message in <encrypt()> function
# decode all the blocks from <blocks_list> into a list of ASCII characters
# decrypt <ascii_message_list> using the <private_key> and <product_of_prime_numbers>
# print <decrypted_message>
def decrypt(private_key: int, product_of_prime_numbers: int) -> str:
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


# verifying the decrypted message func
# the decrypted message must have a maximum of 128 characters
# if it has more than that, the code will ask for another message
# until it has the correct number of 128 characters
def verify_decrypted_message() -> str:
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


# verifying the main menu inputs func
# if 'encrypt' is selected, the code will verify all the inputs, if they are integers or strings
# using <.isnumeric()> to check if the string is a numerical
# return the <e> and <n> values as integers
def verify_encrypt_inputs() -> int:
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


# verifying the main menu inputs func
# if 'decrypt' is selected, the code will verify all the inputs, if they are integers or strings
# using <.isnumeric()> to check if the string is a numerical
# return <d> and <n> values as integers
def verify_decrypt_inputs() -> int:
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


# generating prime numbers func
# generate 'random' prime numbers with 256 bits (2⁸ bits) or 32 bytes (2⁵ bytes)
# where p is not equal to q
def generate_prime_numbers() -> int:
    while True:
        prime_number_one = generate_prime(256)
        prime_number_two = generate_prime(256)
        if prime_number_one != prime_number_two:
            break
    return prime_number_one, prime_number_two


# generating n and m func
# calculate the product of our prime numbers (n)
# calculate totient (m) -> Φ(n) <phi of n>
def generate_n_and_phi_of_n(prime_number_one: int, prime_number_two: int) -> int:
    n = prime_number_one * prime_number_two
    phi_of_n = (prime_number_one - 1) * (prime_number_two - 1)
    return n, phi_of_n


# generating a public key func
# start with 65537 which is a Fernet prime (2¹⁶ + 1 -> 10000000000000001 in binary)
# using this number provides good security against brute force attacks directly
# use 'e' for 'encrypt' -> public key to encrypt data
# <e> must be between 1 and Φ(n) -> 1 < e < Φ(n)
# and gcd between Φ(n) and <e> must be equal 1 -> gcd(Φ(n), e) == 1
def generate_public_key(phi_of_n: int) -> int:
    for i in range(65537, phi_of_n):
        if phi_of_n % i != 0:
            if gcd(phi_of_n, i) == 1:
                public_key = i
                return public_key


# generating a private key func
# <d> is the product of <d> and <e> divided by Φ(n)
# and the result must have a remainder of 1 -> (d * e) % Φ(n) == 1
# use 'd' for 'decrypt' -> private key to decrypt data
# using pow(public_key, -1, Φ(n)) to find <d> -> d = pow(e, -1, m)
# this is the modular inverse algorithm to find <d>
def generate_private_key(public_key: int, phi_of_n: int) -> int:
    private_key = pow(public_key, -1, phi_of_n)
    return private_key


# main menu func
# creating a interactive menu for the users
# input which option you choose
# use <match-case> statement to verify the <option> variable
# define which <case> you choose
# and execute the code inside it
def menu():
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


# main func
# executes when the file is directly executed and starts running
# all the funcs to generate the <cipher_text> and <decrypted_message>
def main():
    menu()


# use this conditional to verify if the file is directly executed
# just one best practice
if __name__ == "__main__":
    main()
