from gmpy2 import isqrt
from Crypto.Util.number import long_to_bytes

n = 148758140571519421113103657438725449613091209272451250208345488213767494166740418153678486394123859994826784382971575831748913972673953192679356299127135305250669651025353730293494690699010974989511388419217506874603689794779387912343290731259378025826316663851302062354499790429450768533840608076501292838043
e = 65537
ct = 121103834251439447845049371291443489363297347007767183079522603281240675771017341325728082357866466317879791821058958269818242514262904813657519801607485317972870937212797500399259621229170271985806218797274374508708675534308443372501845559069858276556876266096324440310015904077270866746885033298268223860231

# Fermat's factorization
# On server side after computing p, q is generated with next_prime(p) which finds the next prime number after p
# Since p and q are close then we can use the fermat algorithm. Starts with a=b=isqrt(n) and then increase a at each
# step and recomputes b. In this case just one iteration is enough!

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
m = pow(ct, d, n)
flag = long_to_bytes(m)
print(flag.decode())
