import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn
from Crypto.Util.number import long_to_bytes

# approach LSB oracle -> it's leaking the lsb

server = pwn.remote("130.192.5.212", 6647)

n = int(server.recvline().decode())
c = int(server.recvline().decode())
e = 65537

lower_bound = 0
upper_bound = n

for i in range(n.bit_length()):
    c = (pow(2, e, n) * c) % n
    server.sendline(str(c).encode())
    bit = int(server.recvline().decode())
    if bit == 1:
        lower_bound = (lower_bound + upper_bound) // 2
    else:
        upper_bound = (lower_bound + upper_bound) // 2

print(long_to_bytes(int(upper_bound)).decode())
print(long_to_bytes(int(lower_bound)).decode())
