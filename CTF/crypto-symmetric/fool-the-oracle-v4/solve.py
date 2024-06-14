import pwn
from Crypto.Cipher import AES
import string
from Crypto.Util.Padding import pad

server = pwn.remote("130.192.5.212", 6544)
block_size = AES.block_size
secret_length = 36 + len("CRYPTO23{}")

'''
On server side AES in ECB mode -> ACPA attack

'*' is the character to try in string.printable 
(pad) is the padding to reach the block size 
(spad_*) is the pad that will be added on the server part 
+ is the 'shift' that will shift of one character the end of the last block

Iterate with all 6 possible padding. Compute the pad1 length and pad2 length same as the server is doing. 
With (spad_1) = 1 and (spad_2) = 10 - 1 = 9
flag length = 46

   (1)   0-16              16-32           32-48   (6)        (3)     48-64             64-80               80-96          96-112
(spad_1)AAAAAAAAAAAAAAA | * (pad) | +BBBBBBBCC   (spad_2) | (spad_2) CRYPTO23{//// | //////////////// | //////////////// | / (pad) |

Then we compare block 16-32 and block 96-112 -> * (pad) == / (pad). If true we save the secret then we shift with shift+1 
every time pushing another char of the flag on the last block.

When the block 16-32 is composed then we move it to the right (secret[:15]) leaving space for a new char to guess 

AAAAAAAAAAa0-500b51857e63}++++++++++++++++BBBBBBBBBBBBCC
at the next step shift to right and the } goes away and leaves space on the left
AAAAAAAAAA0a0-500b51857e63+++++++++++++++++BBBBBBBBBBBBCC

'''
for j in range(1, 7):
    secret = ''
    pad1 = j
    pad2 = 10 - j
    for i in range(secret_length):
        b1 = b"A" * (block_size - pad1)
        b2 = b"B" * (block_size - pad2)
        b3 = b"C" * (block_size - (secret_length % block_size))
        shift = b"+" * (i + 1)

        found = False
        for chr in string.printable:
            if i < block_size - 1:
                tosend = b1 + pad((chr + secret).encode(), block_size) + shift + b2 + b3
            else:
                tosend = b1 + chr.encode() + secret[:15].encode() + shift + b2 + b3

            print(tosend)
            server.recvlines(4)
            server.sendline(b"enc")
            server.sendline(tosend.hex().encode())

            res = server.recvline().decode().strip()
            ct = bytes.fromhex(res.split("> ")[2])

            if ct[16:32] == ct[96: 112]:
                secret = chr + secret
                print(secret)
                found = True
                break
        if not found:
            break

server.close()