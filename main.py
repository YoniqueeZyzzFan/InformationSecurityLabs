from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import argparse
import yaml
from tqdm import tqdm


# Симметричный алгоритм - Blowfish / Вариант 8
# Ассиметричный RSA

def input_length() -> int:
    """
    Эта функция нужна для того, чтобы пользователь ввел число лежащее в пределах [32;448]
    :return: возвращает int значение
    """
    print('Input key length: ')
    length = input()
    while int(length) % 8 != 0 or int(length) < 32 or int(length) > 448:
        print('Invalid key length, the key length is in the range from 32 to 448 and divided by 8 without a remainder')
        print('Input key length: ')
        length = input()
    print('Valid key length')
    return int(length)  


def key_generator(encrypted_symmetrical_key_path: str, public_key_path: str, private_key_path: str) -> None:
    """
    Функция, которая принимает 3 параметра и создает ключи для шифрования.
    :param encrypted_symmetrical_key_path: путь сохранения зашифрованного симметричного ключа
    :param public_key_path: путь сохранения публичного ключа ассиметричного алгоритма
    :param private_key_path: путь сохранения приватного ключа ассиметричного алгоритма
    :return: None
    """
    symmetrical_key = algorithms.Blowfish(os.urandom(input_length()))  # Симметричный ключ
    with tqdm(100, desc='Key generation: ') as progressbar:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key = rsa_key  # Ассиметричный приватный ключ
        public_key = rsa_key.public_key()  # Ассиметричный публичный ключ
        # Сериализация ключей
        # сериализация открытого ключа в файл
        with open(public_key_path + '\\public.pem', 'wb') as public:
            public.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))

        # сериализация закрытого ключа в файл
        with open(private_key_path + '\\private.pem', 'wb') as private:
            private.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
        # шифрование симметричного ключа при помощи RSA-OAEP
        encrypt_symmetrical_key = public_key.encrypt(
            symmetrical_key.key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # сериализация шифрованного симметричного ключа в файл
        with open(encrypted_symmetrical_key_path + '\\encrypted_symmetrical.txt', 'wb') as file:
            file.write(encrypt_symmetrical_key)
        progressbar.update(100)


def encrypt_text_file(path_to_text: str, private_key_path: str, encrypted_symmetrical_key_path: str,
                      path_to_save: str) -> None:
    """
    Это функция шифрования информации, которая принимает 4 параметра
    :param path_to_text: путь к незашифрованному файлу
    :param private_key_path: путь к приватному ключу ассиметричного алгоритма
    :param encrypted_symmetrical_key_path: путь к зашифрованному ключу симметричного алгоритма
    :param path_to_save: путь для сохранения зашифрованного файла
    :return: None
    """
    with open(encrypted_symmetrical_key_path, 'rb') as file:
        encrypted_symmetrical_key = file.read()
    with open(private_key_path, 'rb') as file:
        private_key = serialization.load_pem_private_key(file.read(), password=None)
    # Расшифруем симметричный ключ
    symmetrical_key = private_key.decrypt(
        encrypted_symmetrical_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(path_to_text, 'r') as file:
        text_to_encrypt = file.read()
    padder = padding2.ANSIX923(8).padder()
    text = bytes(text_to_encrypt, 'UTF-8')
    padded_text = padder.update(text) + padder.finalize()
    temp = os.urandom(8)
    cipher = Cipher(algorithms.Blowfish(symmetrical_key), modes.CBC(temp))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text)
    diction = {'encrypted': c_text, 'urandom': temp}
    with open(path_to_save, 'w') as file:
        yaml.dump(diction, file)


def decrypt_text_file(path_to_text: str, private_key_path: str, encrypted_symmetrical_key_path: str, path_to_save: str) -> None:
    """
        Это функция дешифровки информации, которая принимает 4 параметра
        :param path_to_text: путь к зашифрованному тексту
        :param private_key_path: путь к приватному ключу ассиметричного алгоритма
        :param encrypted_symmetrical_key_path: путь к зашифрованному ключу симметричного алгоритма
        :param path_to_save: путь для сохранения расшифрованного файла
        :return: None
        """
    # Расшифровка ключа симм алгоритма
    with open(encrypted_symmetrical_key_path, 'rb') as file:
        encrypted_symmetrical_key = file.read()
    with open(private_key_path, 'rb') as file:
        private_key = serialization.load_pem_private_key(file.read(), password=None)
    symmetrical_key = private_key.decrypt(
        encrypted_symmetrical_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(path_to_text, 'r') as file:
        data = yaml.safe_load(file)
    text_to_decrypt = data["encrypted"]
    urandom = data["urandom"]
    cipher = Cipher(algorithms.Blowfish(symmetrical_key), modes.CBC(urandom))
    decrypt = cipher.decryptor()
    decrypt_text = decrypt.update(text_to_decrypt) + decrypt.finalize()
    unpadder = padding2.ANSIX923(8).unpadder()
    unpadded_decrypt_text = unpadder.update(decrypt_text)
    with open(path_to_save, 'w') as file:
        file.write(str(unpadded_decrypt_text)[2:-1])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="main")
    parser.add_argument(
        "-input_key_save",
        type=str,
        help="Это обязательный строковый позиционный аргумент, который указывает, куда будут сохранены данные о ключах (укажите папку в которую сохранить)",
        dest="keys")
    parser.add_argument(
        "-input_text",
        type=str,
        help="Это обязательный позиционный аргумент, который указывает путь к вашему тексту, который надо зашифровать(зашифрованный появится около обычного)",
        dest="text")
    parser.add_argument(
        "-encrypted_text",
        type=str,
        help="Это обязательный позиционный аргумент, который указывает куда будет сохранен зашифрованный текст",
        dest="save_text")
    parser.add_argument(
        "-decrypted_text",
        type=str,
        help="Это обязательный позиционный аргумент, который указывает куда будет сохранен расшифрованный текст",
        dest="save_d_text")
    args = parser.parse_args()
    key_generator(args.keys, args.keys, args.keys)
with tqdm(100, desc='Encrypting your file: ') as progressbar:
    encrypt_text_file(args.text, args.keys + '\\private.pem', args.keys + '\\encrypted_symmetrical.txt',
                      args.save_text)
    progressbar.update(100)
with tqdm(100, desc='Decrypting your file: ') as progressbar:
    decrypt_text_file(args.save_text, args.keys + '\\private.pem',
                      args.keys + '\\encrypted_symmetrical.txt', args.save_d_text)
    progressbar.update(100)
