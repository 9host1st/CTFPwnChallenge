from Crypto.Util.number import *
from pwn import *
f = open("out.bin", "rb")
p = 65287
q = 65419
e = 201326609
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
print(d)
flag = b""
enc = f.read()
for i in range(0, len(enc), 8):
    tmp = u32(enc[i:i+4])
    r = pow(tmp, d, n)
    flag += p32(r)
print(flag)
