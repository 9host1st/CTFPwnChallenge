from z3 import *
enc = [0x24, 0x27, 0x13, 0xc6, 0xc6, 0x13, 0x16, 0xe6, 0x47, 0xf5, 0x26, 0x96, 0x47, 0xf5, 0x46, 0x27, 0x13, 0x26, 0x26, 0xc6, 0x56, 0xf5, 0xc3, 0xc3, 0xf5, 0xe3, 0xe3]

flag = ""

print(len(enc))
for i in range(len(enc)):
    for j in range(256):
        if((16 * j & 0xf0 | (j >> 4)) == enc[i]):
            flag += chr(j)
print("DH{" + (flag) + "}")
