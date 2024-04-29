from Crypto.Cipher import AES
from math import ceil
import string
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn

'''
    (try)               (flag)
    16   | 16 | 16 | 16 |
                       (flag shift sx 1)
    15+1 | 16 | 16 | 16 |
                      (flag shift sx 2)                       
    14+2 | 16 | 16 | 16 |
      |
       -> 14 = pad if <16 and so on

    after reaching the first full block size 
    (try)         (flag shift sx 1) 
    15+1 | 16 | 16 | 16 |
      |               |-> each time a new byte enters and all of it is compared with shifted secret  
       -> secret is shifted dx 1 (secret[-15:])
'''

server = pwn.remote("130.192.5.212", 6542)
secret_len = len("CRYPTO23{}") + 36
print(secret_len)
blocks_size = ceil(secret_len / AES.block_size) * AES.block_size  # blocks needed to fit the secret with AES

secret = b''

# for each char of the secret
for i in range(secret_len):

    pad_block = b"/" * (AES.block_size - 5)
    # compute the final pad of the remaining undiscovered bytes to add at the end of the message, -1 to leave space for the char to try
    pad = (blocks_size - i - 1) * b'/'
    print(pad, i)
    if i < AES.block_size:
        block = b"/" * (AES.block_size - i - 1)  # if less than 16 bytes block = / (pad) ( - bytes discovered)
    else:
        block = secret[-(AES.block_size - 1):]  # if the first block is full get space for a new byte
    print(block)

    for guess in string.printable:
        if i < AES.block_size:
            message = pad_block + block + secret + guess.encode() + pad  # if < 16 bytes -> / (pad) + bytes discovered + possible char + pad of the remaining bytes to discover
        else:
            message = pad_block + block + guess.encode() + pad # if > 16 bytes -> secret[15] in one block with a space + possible char + pad of the remaining bytes to discover
        print(message, len(message))

        # skip menu
        for output in server.recvlines(4):
            pass
        server.sendline(b"enc")
        server.sendline(message.hex().encode())

        ciphertext = server.recvline().decode().strip().split('> ')[2]
        ciphertext = bytes.fromhex(ciphertext)
        #print(ciphertext)

        # check if the 1st block and the 4th block are equal (ECB)
        if ciphertext[16:32] == ciphertext[blocks_size + 16: blocks_size+32]:
            secret += guess.encode()
            print('----------------------')
            print(secret)
            print('----------------------')
            break

server.close()