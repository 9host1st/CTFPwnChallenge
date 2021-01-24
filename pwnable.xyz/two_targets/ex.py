from z3 import *
from pwn import *
p = remote("svc.pwnable.xyz", 30031)
main_hex = [85, 72, 137, 229, 72, 131, 236, 80, 100, 72, 139, 4, 37, 40, 0, 0, 0, 72, 137, 69, 248, 49, 192, 232, 36, 254, 255, 255, 72, 141, 69, 192]

ans=[0x11, 0xDE, 0xCF, 0x10, 0xDF, 0x75, 0xBB, 0xA5, 0x43, 0x1E, 0x9D, 0xC2, 0xE3, 0xBF, 0xF5, 0xD6, 0x96, 0x7F, 0xBE, 0xB0, 0xBF, 0xB7, 0x96, 0x1D, 0xA8, 0xBB, 0x0A, 0xD9, 0xBF, 0xC9, 0x0D, 0xFF, 0x00]
auth = []
x = BitVec('x', 8)
for i in range(0, 32):
    for j in range(256):
        if((((j >> 4) | (j << 4))^ main_hex[i]) & 0xff) == ans[i]:
            auth.append(chr(j))

print(''.join(auth))
p.sendline("1")
p.send(''.join(auth))

p.sendline("4")

p.interactive()


