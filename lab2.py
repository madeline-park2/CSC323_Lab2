import base64
import binascii
import datetime
import time
import random
from Crypto.Cipher import AES

# Tyler Brady and Madeline Park, Lab 2

### All Helper Functions

def hex_to_bytes(h):
    return binascii.unhexlify(h)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

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
#print(t)
#print(unpad(t))

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
#print(ecb_encrypt(b'1234567890ab', b'1234567890abcdef'))

# Testing ECB Decrypt:
f = open("Lab2.TaskII.A.txt", "r")
text = f.read()
#print(ecb_decrypt(text, b'CALIFORNIA LOVE!'))

# Identify ECB Mode

def is_ecb(msg,):
    #print(msg)
    # check for repeating blocks
    # each block is 16 bytes, so separate into 16s
    # then check if repeating
    # if not, move on
    k = 16
    after_header = 54
    blocks = [msg[i:i+k] for i in range(after_header, len(msg), k)]
    for i in range(len(blocks)):
        if (blocks[i] in blocks[i + 1:]):
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

user_madmin = "fb0dfedc78da2ba160c87a5051721233f09a552e94d6615bad3ea0e5818016ac"

def ecb_cookies():
    k = 16
    example_token = "e62a2b9d87acab2c7972253f1976f37e1061ad4e6d65f79950d75b2c2d11f038"
    in_hex = hex_to_bytes(example_token)
    # in_hex[0:3] == "user", last 4 same
    blocks = [in_hex[i:i+k] for i in range(0, len(in_hex), k)]
    return blocks

print("cookie", ecb_cookies())
#/  
# So assuming that the "role=user" is in the Plaintext block 2,
# we get that through P2 = D(C2) xor C1
# and we want to change C1 so that when we xor it we get "role=admin"
# if we xor 'user' and 'admin' we get a mask
# because of how xor logic works, doing 'user' xor mask gives us 'admin'
# and at a basic level, P2 = 'role=user' = D(C2) xor C1
# plugging this into the 'role=admin' = 'role=user' xor mask
# we get 'role=admin' = (D(C2) xor C1) xor mask
# so we basically want to xor C1 with the mask
# /# 

# user=USERNAMEBBB|BBBBBBBBBB&uid=2|&role=ROLE
# USERNAMEBB&BBBBBBBB
# USERNAMEBBBBBBBBBBBBB

# this is an example token generated from my login
new_token = "0044eb960fb4aa06eb045f881e0120d18594446d9689aed28b540f813009ded3c74cfd4c79bb47af505fc4627555f2e26667079a02113f9ffbddf62160a13581"

new_auth = bytes.fromhex(new_token)

# break it into blocks
blocks = [new_auth[i:i + 16] for i in range(0, len(new_auth), 16)]
print(blocks)
# get the mask
mask = xor_bytes(b'user', b'admin')

# make the block we want a mutable byte array 
mod_block = bytearray(blocks[2])
second_mod_block = bytearray(blocks[0])
# last_symbol = xor_bytes(second_mod_block[-1], b'B')


second_mod_block[-1] ^= ord('B')
second_mod_block[-1] ^= ord('&')
blocks[0] = bytes(second_mod_block)


# Apply the mask - I think we start at index 9 but not sure...
for i in range(len(mask)):
    mod_block[i + 6] ^= mask[i]

# Replace the block
blocks[2] = bytes(mod_block)

modified_cookie = b"".join(blocks)

modified_cookie_hex = modified_cookie.hex()

print(f"Modified Cookie: {modified_cookie_hex}")

### Task III: CBC Mode
# takes an arbitrary length plaintext, 
# a key, and an initialization vector,
# then pads the message
# then encrypts the message and returns the ciphertext
def cbc_encrypt(msg, key, iv):
    # pad the message
    padded_msg = pad(msg)
    k = 16  # block length
    msg_blocks = [padded_msg[i:i+k] for i in range(0, len(padded_msg), k)]
    cipher_blocks = []
    cipher_blocks.insert(0, iv)
    # encrypt the message
    for i in range(len(msg_blocks)):
        encrypted = AES.new(key, AES.MODE_ECB)
        # xor iv with m0, encrypt with key,
        # xor next block with c0, encrypt with key, etc.
        ci = encrypted.encrypt(xor_bytes(msg_blocks[i], cipher_blocks[i]))
        cipher_blocks.append(ci)
    
    final = b''.join(cipher_blocks)
    return final


def cbc_decrypt(ct, key):
    k =  16
    encrypted = AES.new(key, AES.MODE_ECB)
    formatted = base64.b64decode(ct)
    msg_lst = []
    if (len(formatted) % 16 != 0):    # also caught in unpad so maybe extra?
        raise Exception("Length is not a multiple of blocksize.")
    ct_blocks = [formatted[i:i+k] for i in range(0, len(formatted), k)]
    for i in range(len(ct_blocks) - 1, 0, -1): # so that we can go backwards
        padded_msg = encrypted.decrypt(ct_blocks[i])
        msg = xor_bytes(padded_msg, ct_blocks[i - 1])
        msg_lst.insert(0, msg)
    final_msg = b''.join(msg_lst)

    final = unpad(final_msg)
    return final
    

# Testing CBC Encrypt
#print(base64.b64encode(cbc_encrypt(b'hello', b'aesEncryptionKey', b'thisisanivplease')))

# Testing CBC Decrypt
#print(cbc_decrypt(base64.b64encode(cbc_encrypt(b'hello', b'aesEncryptionKey', b'thisisanivplease')),
#                  b'aesEncryptionKey'))

f = open("Lab2.TaskIII.A.txt", "r")

text = f.read()
print(cbc_decrypt(text, b'MIND ON MY MONEY'))

# CBC Cookies

#/  
# So assuming that the "role=user" is in the Plaintext block 2,
# we get that through P2 = D(C2) xor C1
# and we want to change C1 so that when we xor it we get "role=admin"
# if we xor 'user' and 'admin' we get a mask
# because of how xor logic works, doing 'user' xor mask gives us 'admin'
# and at a basic level, P2 = 'role=user' = D(C2) xor C1
# plugging this into the 'role=admin' = 'role=user' xor mask
# we get 'role=admin' = (D(C2) xor C1) xor mask
# so we basically want to xor C1 with the mask
# /# 

# user=USERNAMEBBB|BBBBBBBBBB&uid=2|&role=ROLE
# USERNAMEBB&BBBBBBBB
# USERNAMEBBBBBBBBBBBBB

# this is an example token generated from my login
new_token = "0044eb960fb4aa06eb045f881e0120d18594446d9689aed28b540f813009ded3c74cfd4c79bb47af505fc4627555f2e26667079a02113f9ffbddf62160a13581"

new_auth = bytes.fromhex(new_token)

# break it into blocks
blocks = [new_auth[i:i + 16] for i in range(0, len(new_auth), 16)]
print(blocks)
# get the mask
mask = xor_bytes(b'user', b'admin')

# make the block we want a mutable byte array 
mod_block = bytearray(blocks[2])
second_mod_block = bytearray(blocks[0])
# last_symbol = xor_bytes(second_mod_block[-1], b'B')


second_mod_block[-1] ^= ord('B')
second_mod_block[-1] ^= ord('&')
blocks[0] = bytes(second_mod_block)


# Apply the mask - I think we start at index 9 but not sure...
for i in range(len(mask)):
    mod_block[i + 6] ^= mask[i]

# Replace the block
blocks[2] = bytes(mod_block)

modified_cookie = b"".join(blocks)

modified_cookie_hex = modified_cookie.hex()

print(f"Modified Cookie: {modified_cookie_hex}")

