import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn

server = pwn.remote("130.192.5.212", 6531)

for i in range(128):
    # skip challenge number
    challenge = server.recvline().decode()
    print(challenge)
    otp = server.recvline().decode().strip().split(": ")[1]
    print("otp: " + otp)

    server.sendline(otp.encode())
    cipher = server.recvline().decode().strip().split(": ")[2]
    print(cipher)

    # skip question "What mode did I use? (ECB, CBC)"
    question = server.recvline().decode()
    print(question)

    cipher1 = cipher[0:32]
    cipher2 = cipher[32:]
    print(cipher1)
    print(cipher2)

    # send answer
    if cipher1 == cipher2:
        print("ECB")
        server.sendline("ECB".encode())
    else:
        print("CBC")
        server.sendline("CBC".encode())
    # show result
    answer = server.recvline().decode()
    print(answer)

# challenge line
print(server.recvline().decode())
server.close()
