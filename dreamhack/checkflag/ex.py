from pwn import *
for i in range(1, 65):
    p = process("./checkflag")
    payload = "DH{" + "\x00" * i + "}"
    print(payload)
    p.sendafter("What's the flag? ",  payload)
    leak = p.recv(1024)
    if("Correct!" in leak):
        print("length : " + str(i))
        break
    p.close()

