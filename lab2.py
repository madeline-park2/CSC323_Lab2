import base64
import datetime
import time
import random
from Crypto.Cipher import AES

def pad(msg):
    
    # Calculate pad length
    padding_length = 16 - (len(msg) % 16)
    
    # Makes a list in the form [2, 2] or [3, 3, 3] or [4, 4, 4, 4], etc
    padding_buffer = bytes([padding_length for _ in range(padding_length)])

    # Concatenates it to plaintext
    msg += padding_buffer
    #print(raw_bytes)

    original_form = base64.b64encode(msg).decode("utf-8")

    return original_form


t = pad(b'1234567812345678123456781234121')

def unpad(msg):
    # get last byte, figure out its value
    # this value is the same size as number of bytes padded
    raw_bytes = base64.b64decode(msg)
    #print(raw_bytes)
    #print(len(raw_bytes))
    # check if string is multiple of blocksize
    if (len(raw_bytes) % 16 != 0):
        raise Exception("Length is not a multiple of blocksize.")
    last = raw_bytes[-1:]
    dec = int.from_bytes(last, byteorder="big")
    dec = int.from_bytes(last, "big")
    # IF THAT IS NOT TRUE: error
    for i in range(dec, 0, -1):
        if (raw_bytes[-dec].to_bytes(1, byteorder="big") != last):
            raise Exception("Number of padded blocks does not match padding value.")
    return raw_bytes[:-dec]

print(t)
print(unpad(t))


def ecb_encrypt(msg, key):

    if len(key) != 16:
        raise Exception("Invalid key length")
    
    padded_msg = pad(msg)

    formatted = base64.b64decode(padded_msg)

    encrypted = AES.new(key, AES.MODE_ECB)

    final = encrypted.encrypt(formatted)

    return final

print(ecb_encrypt(b'1234567890ab', b'1234567890abcdef'))