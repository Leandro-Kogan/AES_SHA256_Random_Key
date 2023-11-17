import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
    pad_length = AES.block_size - len(s) % AES.block_size
    return s + bytes([pad_length] * pad_length)

def aesenc(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

plaintext = open(sys.argv[1], "rb").read()

ciphertext = aesenc(plaintext, KEY)

print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
