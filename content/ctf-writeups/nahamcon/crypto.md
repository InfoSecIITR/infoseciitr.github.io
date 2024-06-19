---
layout: post
title: Nahamcon CTF 2024 | Crypto-Writeups
date: 2024-05-26
tags: ['Nahamcon_CTF_2024']
math: True
---

# crypto/Encryption Server writeup
author: Jstith

## Challenge Description
>I read online it's bad to re-use the prime numbers in RSA. So, I made this server that randomly generates them for me.  
**Attachments**: [RSA_Encryption_Server.py](../assets/RSA_Encryption_Server.py)

## Solution

Let's start analysing the code. We can notice a few things:

```py
e = random.randint(500,1000)

def encrypt(inp):
	p = nextprime(randbits(1024))
	q = nextprime(randbits(1024))
	n = p * q
	c = [pow(ord(m), e, n) for m in inp]
	return [n, c]

```
$\text{Observation 1.}$ $e$ is a random integer such that: $e \in [500, 1000)$. Also, a very important fact is that $e$ **remains same for all subsequent encryptions**.  

$\text{Observation 2.}$ The encrypt function is standard $\text{RSA Algorithm}$ using $2048$ bit public modulus and $e$ as the exponent, except the ciphtertext is generated a bit differently then the starndard method: It takes each character of the input string and encrypts it's $\text{ASCII}$ value using $\text{RSA}$. The ciphertext is a list of these encrypted integers.

In the main function, we can see that:
```py
...
elif('1' in inp):
    plain = input('Enter a message, and the server will encrypt it with a random N!\n> ')
    encrypted = encrypt(plain)

elif('2' in inp):
    data = open('flag.txt', 'r').read()
    data = data.strip()
    encrypted = encrypt(data)
...
print('Your randomly chosen N:')
print(f'> {encrypted[0]}')
print('Your encrypted message:')
print(f'> {encrypted[1]}')
print('\n')
...
```

$\text{Exploiting Observation 1.:}$
The program allows us to encrypt a custom input value and gives us the modulus and ciphertext. Since we know what the value is (as we put chose it), and $e$ has a very small range, we can brute force the value of $e$ in the range to find for what $e$, the input value gives the same ciphertext as we received (as encryption doesn't require private key $p$ and $q$). And since $e$ remains same for all encryptions, we will have some more information to work with.

$$m^{\boxed{e}} \equiv c \, (\text{mod } n)$$

Code:
```py
# send '1' as the input
# receive 'n' as modulus and 'c' as ciphertext[0]
e = -1
for i in range(500, 1000):
    if pow(ord('1'), i, n) == c:
        e = i
        print(f'{e=}')
        break
```

$\text{Exploiting Observation 2.:}$ Since the ciphertext values are just encrypted $\text{ASCII}$ values, this gives us only $256^*$ possible values ($1$ byte) for each character in the input string. Since we know $n$, $c$ and now $e$, we can brute force these possible values similar to what we did earlier and obtain the flag.

\* We can reduce this even further by only brute forcing through printable $\text{ASCII}$ characters only.

$$\boxed{m}^e \equiv c \, (\text{mod } n)$$

Code:
```py
import string
valid = string.printable

# receive 'n' as modulus an 'ciphertext' as list
flag = ''
for c in ciphertext:
    for v in valid:
        if pow(ord(v), e, n) == c:
            flag += v
            break

print(flag)
```

## Script

```py
from pwn import *

# context.log_level = 'CRITICAL'

r = process(['python', 'RSA_Encryption_Server.py'])
# r = remote('challenge.nahamcon.com', 30888)

r.sendlineafter(b'> ', b'1')

r.sendlineafter(b'> ', b'1')
r.recvuntil(b'> ')
n = int(r.recvline().decode().strip())

print(f'{n=}')

r.recvuntil(b'> ')
c = int(r.recvline().decode().strip()[1:][:-1])

print(f'{c=}')

e = 0
for i in range(500, 1000):
    if pow(ord('1'), i, n) == c:
        e = i
        print(f'{e=}')
        break
    
r.sendlineafter(b'> ', b'2')

r.recvuntil(b'> ')
n = int(r.recvline().decode().strip())

r.recvuntil(b'> ')
ciphertext = eval(r.recvline().decode().strip())

import string
valid = string.printable

flag = ''
for c in ciphertext:
    for v in valid:
        if pow(ord(v), e, n) == c:
            flag += v
            break

print(flag)
# flag{29070b0688f398587d41041f4b25d8a3}
```

# scripting/Encryption Server writeup
author: Jstith

## Challenge Description
>I created a server to manage all my encrypted data from my lucrative ransomware business. It's still in development, but I should be okay as long as.. wait, what? Somebody leaked a log file??  
**Attachments**: [server.py](../assets/server.py) [decryption_server.log](../assets/decryption_server.log)

## Solution

```py
def decrypt(encrypted):
    key = open('key.txt').read()
    key = key.strip()
    log.print("Key loaded for encrypted message")

    factor = len(encrypted) // len(key) + 1
    key = key * factor
    log.print(f"Key expanded by factor of {factor}")
    key_bytes = key.encode()

    enc_bytes = base64.b64decode(encrypted)
    dec_bytes = bytearray()

    for i in range(len(enc_bytes)):
        dec_bytes.append(enc_bytes[i] ^ key_bytes[i])
        log.print(f"Partial message digest is {md5(dec_bytes).hexdigest()}")
    decrypted = dec_bytes.decode()
    log.print("Message fully decrypted, ready to send...")
    return decrypted
```

We'll solve this in $2$ parts:
1. Finding the $\text{key}$
2. Decoding the messages

### 1. Finding the $\text{key}$


We can start with any message which has $\text{key}$ expansion factor of at least $2$. Because, if it is $1$, it could mean that the whole $\text{key}$ was not used and would only yield partial $\text{key}$.

Analysing the logs, the second message looks perfect for this:

```
20/05/2024 15:15:02	Connection received from ('10.10.2.6', 35450)
... Received encrypted message FCscMQoGXUYTJDYgFzFKEzZEL3kYCBZKCWcSHQEDWQ49K1w=
... Key loaded for encrypted message
... Key expanded by factor of 2
... Partial message digest is dfcf28d0734569a6a693bc8194de62bf
... Partial message digest is c6a675552648c0becb8283f05c172483
... Partial message digest is 4804dc3c133b11589338a62893ae614c
... Partial message digest is 624aa1a206e09836e3c81ea95502f459
... Partial message digest is dc9eca234ddb7ab22cb994d2d65a9190
... Partial message digest is 5cb4c355ef76c07357dc7420a78224c8
... Partial message digest is 0db377921f4ce762c62526131097968f
... Partial message digest is 11676af7565a3e9e7d0b8662e5439dcf
... Partial message digest is 1b78f60ca3cd02d678795acb0a5d09dd
... Partial message digest is c28ccaeb4c42b9bc57eadcc45db0fc97
... Partial message digest is ab05664abb19119940f6f1e12be33f06
... Partial message digest is 938a6f10853b1f1d62fb12f381b01f89
... Partial message digest is cdc22bdf25fe7fd49622ca56eded7d52
... Partial message digest is a7407b6278491cf787cfa5201ee635fc
... Partial message digest is 84f692df69b2e66d165289d13e75fa74
... Partial message digest is 3dfbb7a1f6aea16d2fb554615474f731
... Partial message digest is d243ff13077ff7eadacebe5972967ce6
... Partial message digest is e6392f7be2ea073cc4bd2a640b2a0423
... Partial message digest is dac7d5e859297e861c83eef8d0784f7f
... Partial message digest is 44d556571a1a39834bafe1946ede1edb
... Partial message digest is 097086fe780f7454d565a5f51ba8e967
... Partial message digest is 20fd53360cf6443ac72ca108b8a9ff28
... Partial message digest is 95ee5f72875a554d576c56e8dfe4ed54
... Partial message digest is 760abed0bb169a16c4aa95e845f10517
... Partial message digest is 135f264aa1d5d886471e88c944704db8
... Partial message digest is af449bca97466f556bcc77c6150eb013
... Partial message digest is 468ad9f05ca6e30a202d62970628c04f
... Partial message digest is e044ab23133491e4dc010439fd5b4976
... Partial message digest is 8588f19d7260886758371d53bdcfee94
... Partial message digest is 7a14ba71a3bdb19082ef352a25ed60cc
... Partial message digest is 7935dad11bb4e8a6fac4f9bf1b931c4d
... Partial message digest is 379a4ad6c7fac41cf73a69ee95bea6b4
... Partial message digest is 2fe14f88d52754c9bd169850924637ec
... Partial message digest is 4ca0e08a0f9de1f3b19066cadd31dcf7
... Partial message digest is c020be146a34acea950d12dc512404e3
... Message fully decrypted, ready to send...
... Decrypted message sent!
```

Now, we just need to brute force each byte of the $\text{key}$ in the range $[0,255]$ and keep matching the results with the provided $\text{md5}$ hashes.

Code:
```py
import base64 import b64decode
from hashlib import md5

# copied from the 2nd message in decryption_server.log
hashes = [
    'dfcf28d0734569a6a693bc8194de62bf',
    'c6a675552648c0becb8283f05c172483',
    '4804dc3c133b11589338a62893ae614c',
    '624aa1a206e09836e3c81ea95502f459',
    'dc9eca234ddb7ab22cb994d2d65a9190',
    '5cb4c355ef76c07357dc7420a78224c8',
    '0db377921f4ce762c62526131097968f',
    '11676af7565a3e9e7d0b8662e5439dcf',
    '1b78f60ca3cd02d678795acb0a5d09dd',
    'c28ccaeb4c42b9bc57eadcc45db0fc97',
    'ab05664abb19119940f6f1e12be33f06',
    '938a6f10853b1f1d62fb12f381b01f89',
    'cdc22bdf25fe7fd49622ca56eded7d52',
    'a7407b6278491cf787cfa5201ee635fc',
    '84f692df69b2e66d165289d13e75fa74',
    '3dfbb7a1f6aea16d2fb554615474f731',
    'd243ff13077ff7eadacebe5972967ce6',
    'e6392f7be2ea073cc4bd2a640b2a0423',
    'dac7d5e859297e861c83eef8d0784f7f',
    '44d556571a1a39834bafe1946ede1edb',
    '097086fe780f7454d565a5f51ba8e967',
    '20fd53360cf6443ac72ca108b8a9ff28',
    '95ee5f72875a554d576c56e8dfe4ed54',
    '760abed0bb169a16c4aa95e845f10517',
    '135f264aa1d5d886471e88c944704db8',
    'af449bca97466f556bcc77c6150eb013',
    '468ad9f05ca6e30a202d62970628c04f',
    'e044ab23133491e4dc010439fd5b4976',
    '8588f19d7260886758371d53bdcfee94',
    '7a14ba71a3bdb19082ef352a25ed60cc',
    '7935dad11bb4e8a6fac4f9bf1b931c4d',
    '379a4ad6c7fac41cf73a69ee95bea6b4',
    '2fe14f88d52754c9bd169850924637ec',
    '4ca0e08a0f9de1f3b19066cadd31dcf7',
    'c020be146a34acea950d12dc512404e3',
]

enc_msg = b'FCscMQoGXUYTJDYgFzFKEzZEL3kYCBZKCWcSHQEDWQ49K1w='
enc_bytes = b64decode(msg)

key = ''
i = 0
dec_bytes = bytearray()
for e in enc_bytes:
    for k in range(256):
        d = dec_bytes[:]
        d.append(k ^ e)
        if md5(d).hexdigest() == hashes[i]:
            dec_bytes = d
            i += 1
            key += chr(k)
            break
print(key)
# SNrTxg1fXAXOuXf3O+ZYyzsjhGprmgyaSNr
```

So, the $\text{key}$ must be $\text{``SNrTxg1fXAXOuXf3O+ZYyzsjhGprmgya"}$ as the last few characters are just first few characters repeated .

### 2. Decoding the messages

Now, using this $\text{key}$, we can decode all the messages.

Code:
```py
from itertools import cycle
from base64 import b64decode

key = b'SNrTxg1fXAXOuXf3O+ZYyzsjhGprmgya'

# copied from the decryption_server.log
enc_msgs = [
    b'GyseOBdHRQ49Mz1h',
    b'FCscMQoGXUYTJDYgFzFKEzZEL3kYCBZKCWcSHQEDWQ49K1w=',
    b'CiEHJlgKXhA9bw==',
    b'CiEHdB4IXgp2YRFoAz1GUSpONHkNCBIDBiIUUgQJWRg8OwB0GxVIFiwuPz0UKA5Kb0ooLQpaERNIBB8HAxNZJTwhGSFZ',
    b'EjoGNRsMHUYTJDYgFzFHEylHOz4CG0FZDnBCQwwCHwdkLERhGgQJUT1zbH9EbQcGe0o7bEoH',
    b'ACFSIRYEWBAxLTE1EDxIHWE=',
]

dec_msgs = []

for e_msg in enc_msgs:
    msg = b64decode(e_msg)
    d_msg = ''
    for m, k in zip(msg, cycle(key)):
        d_msg += chr(m ^ k)
    dec_msgs.append(d_msg)
    
print(*dec_msgs, sep='\n')
```

Output:
```
Hello there.
General Kenobi, you are a bold one.
Your move.
You fool. I've been trained in your cryptography arts by Count Dooku!
Attack, Kenobi! flag{a23f721aeff7b65bc87e24015a54aa53}
So uncivilized...
```
