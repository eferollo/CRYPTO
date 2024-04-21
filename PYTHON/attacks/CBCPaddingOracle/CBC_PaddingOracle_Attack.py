import os

from Crypto.Cipher import AES

os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

from myconfig import HOST, PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext

if __name__ == "__main__":
    '''server = remote(HOST, PORT)
    server.send(iv)
    server.send(ciphertext)
    respose = server.recv(1024)
    print(respose)
    server.close()

    server = remote(HOST, PORT)
    server.send(iv)
    edt = bytearray(ciphertext)
    edt[-1] = 0
    server.send(edt)
    respose = server.recv(1024)
    print(respose)
    server.close()'''

#-------------------------------

    print(len(ciphertext) // AES.block_size)
    N = len(ciphertext) // AES.block_size
    initial_part = ciphertext[:(N-2)*AES.block_size]  # all the blocks except for the last 2
    block_to_modify = bytearray(ciphertext[(N-2)*AES.block_size:(N-1)*AES.block_size])
    last_block = ciphertext[(N-1)*AES.block_size:]

    # to modify the last block we have to operate on the last byte of the n-1 block which is "block_to_modify"
    byte_index = AES.block_size - 1
    c_15 = block_to_modify[byte_index]

    for c_prime_15 in range(256):
        block_to_modify[byte_index] = c_prime_15
        to_send = initial_part + block_to_modify + last_block

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        respose = server.recv(1024)
        #print(respose)
        server.close()

        if respose == b'OK':
            print("c_prime_15=" + str(c_prime_15))
            p_prime_15 = c_prime_15 ^ 1
            p_15 = p_prime_15 ^ c_15
            print("p_prime_15=" + str(p_prime_15))
            print("p_15=" + str(p_15))

    p_prime_15 = 191
    print("-----------------------")

    c_second_15 = p_prime_15 ^ 2
    block_to_modify[byte_index] = c_second_15

    byte_index -= 1
    c_14 = block_to_modify[byte_index]

    for c_prime_14 in range(256):
        block_to_modify[byte_index] = c_prime_14
        to_send = initial_part + block_to_modify + last_block

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        respose = server.recv(1024)
        server.close()

        if respose == b'OK':
            print("c_prime_14=" + str(c_prime_14))
            p_prime_14 = c_prime_14 ^ 2
            p_14 = p_prime_14 ^ c_14
            print("p_prime_14=" + str(p_prime_14))
            print("p_14=" + str(p_14))

    print("-----------------------")
