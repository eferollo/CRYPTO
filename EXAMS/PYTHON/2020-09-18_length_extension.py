# Mallory has sniffed from the network a message m and a keyed
# digest sniffed_kdgst computed with the following Python code
#
# from hashlib import sha1
# h = sha1()
# h.update(key+m)
# sniffed_kdgst = h.hexdigest()
#
# and wants to perform a length extension attack that appends
# the content of the data_to_append variable
#
# Starting from the pure Python implementation of the Sha1
# algorithm available at the link below
#
# The objective of this exercise is to:
# - List the functions to modify to mount the length extension attack
# - Write the modifications to the python code to implement the length extension attack
#
# Assume that Mallory knows that len(key+m) is less than the size of one SHA1 block.
#
# Also assume that she accesses the sniffed keyed digest value and data to append by means of the
# following imported global variables
#
# from mydata import sniffed_kdgst
# from mydata import data_to_append # bytes
#
# and that the modified main() function must print out the result
# with the following code (i.e., avoid modifying the main unless you have)
# a very good solution)

# function to be modified:

# 1) init(self,s) -> substitute IV with sniffed dgst

def __init__(self,s):
    self.__H = [None] * 5
    for i in range(5):
        self.__H[i] = int("0x" + sniffed_dgst[i * 8:(i + 1) * 8], 16)
    print(self.__H)

def main():
    hasher = SHA1()
    hasher.update(data_to_append)
    print(hasher.hexdigest())

