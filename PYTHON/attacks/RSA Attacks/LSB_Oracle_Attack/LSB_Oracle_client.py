import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote

from myconfig import HOST,PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

import decimal
def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")

if __name__ == '__main__':

    '''server = remote(HOST, PORT)
    server.send(ciphertext.to_bytes(n.bit_length(), byteorder='big'))
    bit = server.recv(1024)
    print(bit)
    server.close()'''

    decimal.getcontext().prec = n.bit_length()
    upper_bound = decimal.Decimal(n)
    lower_bound = decimal.Decimal(0)
    print(lower_bound, upper_bound)

    m = ciphertext
    for i in range(n.bit_length()):
        m = (pow(2, e, n) * m) % n
        server = remote(HOST, PORT)
        server.send(m.to_bytes(n.bit_length(), byteorder='big'))
        bit = server.recv(1024)
        print(bit)
        server.close()

        if bit[0] == 1:
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2

        print_bounds(lower_bound, upper_bound)

    print(int(upper_bound).to_bytes(n.bit_length(), byteorder='big').decode())
