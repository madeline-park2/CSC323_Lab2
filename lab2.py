import base64
import binascii
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

# Testing pad and unpad
t = pad(b'123456781234567812345678123412')
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

def hex_to_bytes(h):
    return binascii.unhexlify(h)
    
def is_ecb(msg):
    #print(msg)
    # check for repeating blocks
    # each block is 16 bytes, so separate into 16s
    # then check if repeating
    # if not, move on
    k = 16
    after_header = 54
    chunks = [msg[i:i+k] for i in range(after_header, len(msg), k)]
    if (chunks[0] in chunks[1:]):
        return msg
    return None

# Testing for is_ecb
f = open("Lab2.TaskII.B.txt", "r")
for i in range(100):
    text = f.readline().strip()
    byte_text = hex_to_bytes(text)
    if (is_ecb(byte_text) is not None):
        with open("TaskII.B.image.png", "wb") as binary_file:
            binary_file.write(byte_text)


# ECB Cookies

### Task III: CBC Mode
