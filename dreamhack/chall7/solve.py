from z3 import *

def ROL(data, shift, size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size )
    return (body + remains)

def ROR(data, shift, size=32):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)

enc = "R\xDF\xB3`\xF1\x8B\x1C\xB5W\xD1\x9F8K)\xD9&\x7F\xC9\xA3\xE9S\x18O\xB8j\xCB\x87X[9\x1E\x00"
flag = ""
for i in range(len(enc)):
    tmp = (ROR(ord(enc[i]) ^ i, i & 7)) % 255
    flag += chr(tmp)

print("DH{" + flag + "}")

