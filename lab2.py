import base64
import datetime
import time
import random

def pad(msg, blockSize):
    
    # Convert to bytes
    msg_bytes = msg.encode("utf-8")

    # Calculate pad length
    padding_length = blockSize - (len(msg) % blockSize)

    if padding_length == blockSize:
        # Add an entire block
        return
    
    # Makes a list in the form [2, 2] or [3, 3, 3] or [4, 4, 4, 4], etc
    padding_buffer = bytes([padding_length for _ in range(padding_length)])

    # Concatenates it to plaintext
    msg_bytes += padding_buffer

    print(msg_bytes)

    return

pad("1234567890", 3)