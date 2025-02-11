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

    original_form = base64.b64encode(raw_bytes).decode("utf-8")

    return original_form


pad("1234567890ab")