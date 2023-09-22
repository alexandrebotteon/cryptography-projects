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