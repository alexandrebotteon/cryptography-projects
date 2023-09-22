from libnum import generate_prime
from math import gcd
from zlib import compress, decompress
from base64 import b64encode, b64decode
from os import system

def encrypt(public_key: int, product_of_prime_numbers: int) -> str:
    message = input('Input your decrypted message: ')
    ascii_message = [ord(char) for char in message]
    cipher_text_bytes = b''.join([pow(ascii_number, public_key, product_of_prime_numbers).to_bytes(64, byteorder='big') for ascii_number in ascii_message])
    compressed_cipher_text = compress(cipher_text_bytes)
    cipher_text = b64encode(compressed_cipher_text).decode('utf-8')
    return cipher_text