import base64
from Crypto.Cipher import AES

# Tyler Brady and Madeline Park, Lab 2

### All Helper Functions

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
    byte_text = bytes.fromhex(text)
    if (is_ecb(byte_text) is not None):
        with open("TaskII.B.image.png", "wb") as binary_file:
            binary_file.write(byte_text)

# ECB Cookies

# cookie: user=00000000000admin0000000000000&uid=501&role=user
# admin + user are in own blocks, at start of block
# paste admin block on end where user block is
# then fix padding: user would be \x0C but admin would be \x0B


c = "348cb8d538c470a8e81dd8f38934a74d4deb81123f86cc77d5f01a01a6b66bef3bea9e08bf8d59376348d78bca0bedb0c8ee374d6a294bfa5890872c4a7e05f7"
in_hex = bytes.fromhex(c)
blocks = [in_hex[i:i+16] for i in range(0, len(in_hex), 16)]
# second block = "admin00000000000"
# last block = "user" and proper padding, ending with \x0C
last_block = bytearray(blocks[3])
print(last_block)
last_block[0:4] = blocks[1][0:4]
print(last_block, blocks[1])
last_block[-1] ^= 0x0C ^ 0x0B
print(last_block)
blocks[3] = last_block
new_cookie = b"".join(blocks)
print(new_cookie.hex())


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
print(base64.b64encode(cbc_encrypt(b'hello', b'aesEncryptionKey', b'thisisanivplease')))

# Testing CBC Decrypt
print(cbc_decrypt(base64.b64encode(cbc_encrypt(b'hello', b'aesEncryptionKey', b'thisisanivplease')),
                  b'aesEncryptionKey'))

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

# USERNAMEBBBBBBBBBBBBB

# Grab the token from logging in
new_token = "c46ae68102cfa19b4051b70f8d36e13ea866c305aa6bed2cf880e250739950451da546874cd0b64b88a07548aaf1ff01"

# Convert to bytes
new_auth = bytes.fromhex(new_token)

# Break it into blocks
blocks = [new_auth[i:i + 16] for i in range(0, len(new_auth), 16)]

# Create a duplicate of the first block as a dummy block 
dummy = bytes(blocks[1])

# Insert the dummy block
blocks.insert(2, dummy)
for i, block in enumerate(blocks):
    print(f"\nBlock {i}: {block.hex()} ({block})\n")


# Get the mask to change 'user' to 'admin'
mask = xor_bytes(b'user\x00', b'admin')


# Make the block we want a mutable byte array 
mod_block = bytearray(blocks[2])

# 'user' is one character shorter than 'admin' so we need to adjust padding
# Normally the padding would have 0x06 at the end but we need it to be 0x05 now
# XOR 0x06 to zero it out then XOR 0x05 to accomodate the longer string
mod_block[-1] ^= 0x06 ^ 0x05

# Apply the mask, skipping the '&role=' part
for i in range(len(mask)):
    mod_block[i + 6] ^= mask[i]

# Replace the block
blocks[2] = bytes(mod_block)


modified_cookie = b"".join(blocks)

modified_cookie_hex = modified_cookie.hex()

print(f"Modified Cookie: {modified_cookie_hex}")

