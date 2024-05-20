from gmpy2 import isqrt
from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes

# Fermat factorization
# On server side after computing p, q is generated with next_prime(p) which finds the next prime number after p
# Since p and q are close then we can use the fermat algorithm. Starts with a=b=isqrt(n) and then increase a at each
# step and recomputes b.
e = 65537
n = 84579385253850209980531118129485716360575269582423585759001305965013034395499445816183248675447710453177558996114910965695049824431833160231360553529286419317374940825879760576417322050461035628520331998356731488662783964882867470865445762024182798458285340930223702904421982112483822508094601373760076526513
c = 17668912838657324025145974741772418705042500725249546941532860274474967308105880488339989276944955996505219230783445824255159192918050910923274393622976856688164873271519593664637389313627158186713709798641755794557335453137110328826176249263923330675599181311888750799280794535134718146446678320514719996743

# p = a+b, q = a-b -> n = pq = a^2 - b^2 -> b = a^2 - n
a = b = isqrt(n)
b2 = pow(a, 2) - n

print("a = " + str(a))
print("b = " + str(b))
print("b2 = " + str(b2))
print("delta-->" + str(pow(b, 2) - b2 % n))
i = 0
while True:
    print("Iteration #" + str(i))
    if b2 == pow(b, 2):
        print("Solution found")
        break
    else:
        a += 1
        b2 = pow(a, 2) - n
        b = isqrt(b2)
        print("a = " + str(a))
        print("b = " + str(b))
        print("b2 = " + str(b2))
        print("delta-->" + str(pow(b, 2) - b2 % n))

    i += 1

p = a + b
q = a - b

# compute the private exponent d = e^-1 % phi(n), phi is possible thanks to p and q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# Use private exponent to decrypt the flag c^d % n
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode())
