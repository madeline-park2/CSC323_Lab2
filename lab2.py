import base64
import datetime
import time
import random

def pad(msg):
    
    # Convert to bytes
    msg_bytes = msg.encode("utf-8")

    # Calculate pad length
    padding_length = 16 - (len(msg) % 16)
    
    # Makes a list in the form [2, 2] or [3, 3, 3] or [4, 4, 4, 4], etc
    padding_buffer = bytes([padding_length for _ in range(padding_length)])

    # Concatenates it to plaintext
    msg_bytes += padding_buffer

    print(msg_bytes)

    return

def unpad(msg):

    if len(msg) % 16 != 0:
        raise Exception("Plaintext has invalid padding")
    


pad("1234567890")