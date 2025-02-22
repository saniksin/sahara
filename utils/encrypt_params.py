import os
import sys
import base64
import getpass

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from settings.settings import USE_PRIVATE_KEYS_ENCRYPTION
from data.config import SALT_PATH, CIPHER_SUITE
from db_api.database import Accounts


def check_encrypt_param():
    if USE_PRIVATE_KEYS_ENCRYPTION:
        if not os.path.exists(SALT_PATH):
            print(f'You need to add salt.dat to {SALT_PATH} for correct decryption of private keys!\n'
                  f'After the program has started successfully, you can delete this file. \n\n'
                  f'If you do not need encryption, please change use_private_key_encryption to False.')
            sys.exit(1)
        with open(SALT_PATH, 'rb') as f:
            salt = f.read()
        user_password = getpass.getpass('[DECRYPTOR] Write here you password '
                                        '(the field will be hidden): ').strip().encode()
        CIPHER_SUITE.append(get_cipher_suite(user_password, salt))


def get_private_key(account: Accounts | dict, create_db: bool = False) -> str | int:
    """
    Извлекает приватный ключ из объекта account (класс или словарь).
    
    Args:
        account: Объект Accounts или словарь с ключами.
        create_db: Флаг, указывающий, возвращать ли сообщение об ошибке вместо завершения программы.
        
    Returns:
        Приватный ключ в виде строки, либо сообщение об ошибке (если create_db=True).
    
    Raises:
        SystemExit: Если невозможно расшифровать ключ и create_db=False.
    """
    try:
        # Определяем источник приватного ключа (атрибут или ключ словаря)
        evm_pk = account.evm_pk if isinstance(account, Accounts) else account['evm_pk']
        
        # Если включено шифрование, расшифровываем ключ
        if USE_PRIVATE_KEYS_ENCRYPTION:
            return CIPHER_SUITE[0].decrypt(evm_pk).decode()

        # Если шифрование выключено, возвращаем ключ как есть
        return evm_pk

    except InvalidToken:
        msg = f"{account.evm_address if isinstance(account, Accounts) else account.get('evm_address', 'Unknown')} | wrong password or salt! Decrypt private key not possible"
        if create_db:
            return msg
        sys.exit(msg)



def get_cipher_suite(password, salt) -> Fernet:
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        return Fernet(key)

    except TypeError:
        print('Error! Check salt file! Salt must be bites string')
        sys.exit(1)