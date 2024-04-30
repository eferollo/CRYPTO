import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn

server = pwn.remote("130.192.5.212", 6532)

challenge = server.recvline().decode()
print(challenge)

# data to send must be 32 bytes long
tosend = b"A" * 32

for i in range(128):
    server.sendline(tosend.hex().encode())
    cipher1 = server.recvline().decode().strip().split(" ")[-1]
    print(cipher1)

    server.sendline(tosend.hex().encode())
    cipher2 = server.recvline().decode().strip().split(" ")[-1]
    print(cipher2)

    # skip question "What mode did I use? (ECB, CBC)"
    question = server.recvline().decode()
    print(question)

    if cipher1 == cipher2:
        print("ECB")
        server.sendline("ECB".encode())
    else:
        print("CBC")
        server.sendline("CBC".encode())

    # show result
    answer = server.recvline().decode()
    print(answer)

    print(server.recvline().decode())

server.close()
