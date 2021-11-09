from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish
from cryptography.hazmat.primitives import padding
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Симметричный алгоритм - Blowfish / Вариант 8
# Ассиметричный RSA

def input_length() -> int:
    print('Input key length: ')
    length = input()
    while int(length) % 8 != 0 or int(length) < 32 or int(length) > 448:
        print('Invalid key length, the key length is in the range from 32 to 448 and divided by 8 without a remainder')
        print('Input key length: ')
        length = input()
    print('Valid key length')
    return int(length)


def key_generator(encrypted_symmetrical_key_path: str, public_key_path: str, private_key_path: str):
    key = Blowfish(os.urandom(input_length())) # Симметричный ключ
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = rsa_key # Ассиметричный приватный ключ
    public_key  = rsa_key.public_key() # Ассиметричный публичный ключ





if __name__ == '__main__':
