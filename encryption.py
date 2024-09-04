# encryption.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from constants import AES_KEY, AES_IV

def encrypt_message(message):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return encrypted_message

def decrypt_message(encrypted_message):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_message.decode()
