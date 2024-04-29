from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn

server = pwn.remote("130.192.5.212", 6552)

username = b"username="
role = b"&admin="

pad1 = b"." * (AES.block_size - len(username))
pad2 = pad(b"true", AES.block_size)
pad3 = b"." * (AES.block_size - len(role))
tosend = pad1 + pad2 + pad3

#        16             32             48              64
# |username=.......| true+pad | .........&admin= | false + pad
print(tosend)

server.sendline(tosend)

cookie = int(server.recvline().decode().strip().split(": ")[1])
cookie = long_to_bytes(cookie)
print(len(cookie))
print(cookie)

true = cookie[16:32]   # |true + pad|
cookie_2 = cookie[:48] + true  # |username=.......| true+pad | .........&admin= | true + pad |

# skip menu
for output in server.recvlines(4):
    print(output.decode())

server.sendline(b"flag")
server.sendline(str(bytes_to_long(cookie_2)).encode())

for output in server.recvlines(4):
    print(output.decode())

server.close()
