import base64
import datetime
import time
import random
from Crypto.Cipher import AES

# Tyler Brady and Madeline Park, Lab 2

### Task I: Padding for Block Ciphers

def pad(msg):
    
    # Calculate pad length
    padding_length = 16 - (len(msg) % 16)
    
    # Makes a list in the form [2, 2] or [3, 3, 3] or [4, 4, 4, 4], etc
    padding_buffer = bytes([padding_length for _ in range(padding_length)])

    # Concatenates it to plaintext
    msg += padding_buffer

    #original_form = base64.b64encode(msg)
    return msg


t = pad(b'123456781234567812345678123412')

def unpad(msg):
    # get last byte, figure out its value
    # this value is the same size as number of bytes padded
    # check if string is multiple of blocksize
    if (len(msg) % 16 != 0):
        raise Exception("Length is not a multiple of blocksize.")
    last = msg[-1:]
    dec = int.from_bytes(last, byteorder="big")
    dec = int.from_bytes(last, "big")
    # IF THAT IS NOT TRUE: error
    for i in range(dec, 0, -1):
        if (msg[-dec].to_bytes(1, byteorder="big") != last):
            raise Exception("Number of padded blocks does not match padding value.")
    return msg[:-dec]

print(t)
print(unpad(t))

### Task II: ECB Mode

# Implement ECB Mode

def ecb_encrypt(msg, key):

    if len(key) != 16:  # 16 bytes -> 128 bits
        raise Exception("Invalid key length")
    
    padded_msg = pad(msg)

    #formatted = base64.b64decode(padded_msg)

    encrypted = AES.new(key, AES.MODE_ECB)

    final = encrypted.encrypt(padded_msg)

    return final

def ecb_decrypt(msg, key):
    # should error on ciphertext is not multiple of blocksize
    # and unpadding returns error
    encrypted = AES.new(key, AES.MODE_ECB)
    formatted = base64.b64decode(msg)
    if (len(formatted) % 16 != 0):    # also caught in unpad so maybe extra?
        raise Exception("Length is not a multiple of blocksize.")
    padded_msg = encrypted.decrypt(formatted)
    final = unpad(padded_msg)

    return final

# Testing ECB Encrypt:
print(ecb_encrypt(b'1234567890ab', b'1234567890abcdef'))

# Testing ECB Decrypt:
f = open("Lab2.TaskII.A.txt", "r")
text = f.read()
print(ecb_decrypt(text, b'CALIFORNIA LOVE!'))

# Identify ECB Mode

# ECB Cookies

### Task III: CBC Mode
