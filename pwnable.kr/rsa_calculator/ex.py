from pwn import *
from Crypto.Util.number import getPrime
from Crypto.Util.number import inverse
from gmpy2 import invert

p = process("./rsa_calculator")
elf = ELF("./rsa_calculator")
libc = elf.libc
def setKey(n1, n2, e, d):
	p.sendlineafter("> ", "1")
	p.sendlineafter("p : ", str(n1))
	p.sendlineafter("q : ", str(n2))
	p.sendlineafter("e : ", str(e))
	p.sendlineafter("d : ", str(d))

def RSAEncrypt(length, data):
	p.sendlineafter("> ", "2")
	p.sendlineafter(":", str(length))
	p.sendlineafter("data", data)

def RSADecrypt(length, data):
	p.sendlineafter("> ", "3")
	p.sendlineafter(":", str(length))
	p.sendlineafter("data", data)

if __name__ == "__main__":
	p1 = getPrime(15)
	p2 = getPrime(15)
	p1 = 25741
	p2 = 24359
	e = 1
	p.info("p : " + str(p1))
	p.info("q : " + str(p2))
	phi = (p1 - 1) * (p2 - 1)
	d = invert(e, phi)
	setKey(p1, p2, e, d)
	pause()
	RSAEncrypt(8, "\xa0"*8)
	p.interactive()

