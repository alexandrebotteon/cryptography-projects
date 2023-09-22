from libnum import generate_prime
from math import gcd
from zlib import compress, decompress
from base64 import b64encode, b64decode
from os import system

def encrypt(public_key: int, product_of_prime_numbers: int) -> str:
    message = verify_decrypted_message()
    ascii_message = [ord(char) for char in message]
    cipher_text_bytes = b''.join([pow(ascii_number, public_key, product_of_prime_numbers).to_bytes(64, byteorder='big') for ascii_number in ascii_message])
    compressed_cipher_text = compress(cipher_text_bytes)
    cipher_text = b64encode(compressed_cipher_text).decode('utf-8')
    return cipher_text

def decrypt(private_key: int, product_of_prime_numbers: int) -> str:
    message = input('Input your encrypted message: ')
    decoded_message = b64decode(message.encode('utf-8'))
    decompressed_data = decompress(decoded_message)
    blocks_list = [decompressed_data[i:i+64] for i in range(0, len(decompressed_data), 64)]
    ascii_message_list = [int.from_bytes(block, byteorder='big') for block in blocks_list]
    decrypted_message = ''.join(chr(pow(ascii_number, private_key, product_of_prime_numbers)) for ascii_number in ascii_message_list)
    return decrypted_message

def verify_decrypted_message() -> str:
    while True:
        message = input('\nInput your decrypted message: ')
        if len(message) <= 128:
            return message
        else:
            system('cls')
            print('The decrypted message must have a maximum of 128 characters!')
            input('\nPress the Enter key to insert a new message. . .')
            system('cls')
            print('ENCRYPTING A MESSAGE')

def verify_encrypt_inputs() -> int:
    while True:
        n = input('\nInput the product of prime numbers (n): ')
        if n.isnumeric():
            while True:
                e = input('\nInput the public key (e): ')
                if e.isnumeric():
                    return int(e), int(n)
                else:
                    system('cls')
                    print('Invalid public key (e)')
                    input('\nPress the Enter key to insert a new public key. . .')
                    system('cls')
                    print('ENCRYPTING A MESSAGE')
        else:
            system('cls')
            print('Invalid product of prime numbers (n)')
            input('\nPress the Enter key to insert a new product of prime numbers. . .')
            system('cls')
            print('ENCRYPTING A MESSAGE')

def verify_decrypt_inputs() -> int:
    while True:
        n = input('\nInput the product of prime numbers (n): ')
        if n.isnumeric():
            while True:
                d = input('\nInput the private key (d): ')
                if d.isnumeric():
                    return int(d), int(n)
                else:
                    system('cls')
                    print('Invalid private key (d)')
                    input('\nPress the Enter key to insert a new private key. . .')
                    system('cls')
                    print('DECRYPTING A MESSAGE')
        else:
            system('cls')
            print('Invalid product of prime numbers (n)')
            input('\nPress the Enter key to insert a new product of prime numbers. . .')
            system('cls')
            print('DECRYPTING A MESSAGE')

def generate_prime_numbers() -> int:
    while True:
        prime_number_one = generate_prime(256)
        prime_number_two = generate_prime(256)
        if prime_number_one != prime_number_two:
            break
    return prime_number_one, prime_number_two

def generate_n_and_phi_of_n(prime_number_one: int, prime_number_two: int) -> int:
    n = prime_number_one * prime_number_two
    phi_of_n = (prime_number_one - 1) * (prime_number_two - 1)
    return n, phi_of_n

def generate_public_key(phi_of_n: int) -> int:
    for i in range(65537, phi_of_n):
        if phi_of_n % i != 0:
            if gcd(phi_of_n, i) == 1:
                public_key = i
                return public_key
