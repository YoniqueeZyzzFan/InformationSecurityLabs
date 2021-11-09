from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish
from cryptography.hazmat.primitives import padding
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


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
    symmetrical_key = Blowfish(os.urandom(input_length()))  # Симметричный ключ
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = rsa_key  # Ассиметричный приватный ключ
    public_key = rsa_key.public_key()  # Ассиметричный публичный ключ
    # Сериализация ключей
    # сериализация открытого ключа в файл
    with open(public_key_path + '\\public.pem', 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # сериализация закрытого ключа в файл
    with open(private_key_path + '\\private.pem', 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    # шифрование симметричного ключа при помощи RSA-OAEP
    encrypt_symmetrical_key = public_key.encrypt(
        symmetrical_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # сериализация шифрованного симметричного ключа в файл
    with open(encrypted_symmetrical_key_path, 'wb') as key_file:
        key_file.write(encrypt_symmetrical_key)
    # Расшифровка ключа симм алгоритма
    with open(encrypted_symmetrical_key_path, 'rb') as key_file:
        ciphertext = key_file.read()
    decrypt_symmetrical_key= private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    if decrypt_symmetrical_key == symmetrical_key:
        print('Its working, wooohoooo!!!!!! ')



if __name__ == '__main__':
