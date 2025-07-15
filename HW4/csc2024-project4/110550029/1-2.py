#!/usr/bin/env python3
'''
# Directly use the PRGN of C library and set the same seeds (the current time) and the random number sequences will be the same
'''
# Run on linux
from pwn import *
import sys
from ctypes import CDLL

libc = CDLL("libc.so.6")
libc.srand(libc.time(0))

if len(sys.argv) < 3:
    r = process(sys.argv[1])
else:
    r = remote(sys.argv[1], int(sys.argv[2]))

ans = ""
for i in range(16):
    ans += chr(48 + (libc.rand() % (126 - 47) + 1))
    
r.recv()
r.sendline(str(ans).encode())
r.recvline()
print(r.recvline().decode())
r.close()
