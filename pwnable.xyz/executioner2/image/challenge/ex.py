from pwn import *

p = process("./challenge")
elf = ELF("./challenge")

p.interactive()
