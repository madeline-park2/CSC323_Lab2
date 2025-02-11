import base64
import datetime
import time
import random

def pad(msg):
    
    raw_bytes = base64.b64decode(msg)

    # Calculate pad length
    padding_length = 16 - (len(msg) % 16)
    
    # Makes a list in the form [2, 2] or [3, 3, 3] or [4, 4, 4, 4], etc
    padding_buffer = bytes([padding_length for _ in range(padding_length)])

    # Concatenates it to plaintext
    raw_bytes += padding_buffer
    #print(raw_bytes)

    original_form = base64.b64encode(raw_bytes).decode("utf-8")

    return original_form


t = pad("1234567890ab")

def unpad(msg):
    # get last byte, figure out its value
    # this value is the same size as number of bytes padded
    raw_bytes = base64.b64decode(msg)
    print(raw_bytes)
    last = raw_bytes[-1:]
    dec = int.from_bytes(last)
    # IF THAT IS NOT TRUE: error
    if (not raw_bytes.count(last) == dec):
        raise Exception("Number of padded blocks does not match padding value.")
    # else return msg - padding
    return raw_bytes[:-dec]

print(t)
print(unpad(t))
