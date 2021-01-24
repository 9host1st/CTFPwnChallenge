e = [0xAD, 0xD8, 0xCB, 0xCB, 0x9D, 0x97, 0xCB, 0xC4, 0x92, 0xA1, 0xD2, 0xD7, 0xD2, 0xD6, 0xA8, 0xA5, 0xDC, 0xC7, 0xAD, 0xA3, 0xA1, 0x98, 0x4C, 0x00]
ret = 0

for i in range(len(e)):
    if i % 2:
        ret += e[i]
    else:
        ret -= e[i]
for i in range(0x30, 0x7f):
    a = [0 for _ in range(25)]
    a[0] = i
    a[24] = a[0] - ret
    for j in range(1, 25):
        a[j] = e[j - 1] - a[j - 1]
    chk = False
    for j in range(25):
        if(a[j] < 0x0):
            chk = True
    if(chk == False):
        for j in range(len(a)):
            a[j] = chr(a[j])
        print("DH{" + ''.join(a) + "}")
