#!/usr/bin/env python

from pwn import *

p = process("./flippidy", env={"LD_PRELOAD": "./libc.so.6"})

def add(idx, content):
   p.sendlineafter(": ", str(1))
   p.sendlineafter("Index: ", str(idx))
   p.sendlineafter("Content: ", content)

def flip():
   p.sendlineafter(": ", str(2))

pause()

p.sendlineafter("To get started, first tell us how big your notebook will be: ", str(3))

add(1, "AAAA")
flip()
#add(4, "CCCC")

p.interactive()
