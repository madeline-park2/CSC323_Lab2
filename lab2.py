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
new_token = "a3f3a6c2364f7203776d65eb035f1ad9fa6956290189603f127a2c8b74a56c46025f264a129533fdd59cbbf3b5f9dceb3ebf96a3225b96ed4221dddb6138472b"

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

# ---------------------------------
print("------------------------------------\n\n")
# user=ZZZZZZZZZZZ|admin&uid=1&role|=user


# user=ZZZZZZZZZZZ|admin00000000000|0000&uid=1&role=|user
# ZZZZZZZZZZZadmin000000000000000
# put block3[1] into block1[3] then put block2[3] into block1[4]

# user=ZZZZZZZZZZZ|admin00000000000|&uid=1&role=user|
# ZZZZZZZZZZZadmin00000000000

# user=ZZZZZZZZZZZ|admin&uid=1&role|=user
# ZZZZZZZZZZZadmin




# user=ZZZZZZZZZZZ|admin&uid=1&role|=user

# user=ZZZZZZZZZZZ|admin           |0000&uid=1&role=|user
# user=ZZZZZZZZZZZ|admin&uid=1&role|=user

# user=ZZZZZZZZZZZ|admin&uid=1&role|=user

# user=ZZZZZZZZZZZ|admin\0\0\0\0\0\0\0\0\0\0\0|0000&uid=1&role=|user


# user=ZZZZZZZZZZZ|admin00000000000|00000&uid=1&role|=user

# user=ZZZZZZZZZZZ|admin00000000000|0000&uid=1&role=|user
# user=ZZZZZZZZZZZ|admin00000000000|0000000000000000|&uid=1&role=user|


# user=ZZZZZZZZZZZ|admin00000000000|&uid=1&role=user|
# user=&uid=1&role|=admin&uid=1&role|=user

# user=tylerrrrrZZ|ZRRR&uid=2&role=|user

# Token 1 should have its last block start with 'user'
# Token 2 provides a full block of padding to tag onto the final cookie
# Token 3 provides a block starting with 'admin' followed by a '&' delimiter
admin_token = "c127dc277fdc0211538a9d20a19781deadfb2153896aec039386a1eccfbdee032204c48b1bb6013a661b56544322b14aed1999e24e61c0142e1fe9818e076675"
other_token = "c127dc277fdc0211538a9d20a19781deadfb2153896aec039386a1eccfbdee0324dc324ac85a000bfd52f31a5dbe495072c7e3c997116ab117d012f71398c87e"
last_token = "c127dc277fdc0211538a9d20a19781de0fb74747a338d154af143ea30c3f02fd20bcd248fb041a61767df322b7fd1c4f"

# Convert to bytes
admin_bytes = bytes.fromhex(admin_token)
other_bytes = bytes.fromhex(other_token)
last_bytes = bytes.fromhex(last_token)

# Break it into blocks
admin_blocks = [admin_bytes[i:i + 16] for i in range(0, len(admin_bytes), 16)]
other_blocks = [other_bytes[i:i + 16] for i in range(0, len(other_bytes), 16)]
last_blocks = [last_bytes[i:i + 16] for i in range(0, len(last_bytes), 16)]

for i, block in enumerate(admin_blocks):
    print(f"\nBlock {i}: {block.hex()} ({block})\n")


# Grab the important blocks we need 
first = bytearray(last_blocks[1]) # admin&...
second = bytearray(other_blocks[3]) # padding

# Arrange them so that the final cookie is in the form:
# | ... role=|admin& ... | pure padding
admin_blocks[3] = bytes(first)
admin_blocks.append(bytes(second))


mod_cookie = b"".join(admin_blocks)

mod_cookie_hex = mod_cookie.hex()

print(f"Modified Cookie ECB: {mod_cookie_hex}")

# user=tylerrrrrZZ|ZRRR&uid=2&role=|admin&uid=1&role|
# need a padding of 11
# user=ZZZZZZZZZZZ|admin00000000000|0000&uid=2&role=|admin00000000000
