---
layout: post
title: BYUCTF 2024 | times-writeup
date: 2024-05-23
tags: ['BYUCTF24']
maths: True
---

# crypto/times [154 Solves] 🩸
## Challenge Description
> It's just multiplication... right?
### Challenge Author
> Author: overllama
---
## Challenge Files
we are provided with a python files and a text file 
```py 
import hashlib
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from ellipticcurve import * # I'll use my own library for this
from base64 import b64encode
import os
from Crypto.Util.number import getPrime

def encrypt_flag(shared_secret: int, plaintext: str):
    iv = os.urandom(AES.block_size)

    #get AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]

    #encrypt flag
    plaintext = pad(plaintext.encode('ascii'), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)

    return { "ciphertext" : b64encode(ciphertext), "iv" : b64encode(iv) }
    
def main():
    the_curve = EllipticCurve(13, 245, getPrime(128))
    start_point = None
    while start_point is None:
        x = getPrime(64)
        start_point = the_curve.point(x)
    print("Curve: ", the_curve)
    print("Point: ", start_point)
    new_point = start_point * 1337

    flag = "byuctf{REDACTED}"
    print(encrypt_flag(new_point.x, flag))

if __name__ == "__main__":
    main()
```
```txt 
Curve:  y^2 = x**3 + 13x + 245 % 335135809459196851603485825030548860907
Point:  (14592775108451646097, 237729200841118959448447480561827799984)
{'ciphertext': b'SllGMo5gxalFG9g8j4KO0cIbXeub0CM2VAWzXo3nbIxMqy1Hl4f+dGwhM9sm793NikYA0EjxvFyRMcU2tKj54Q==', 'iv': b'MWkMvRmhFy2vAO9Be9Depw=='}
```
## Solution
first we must analyse the python file and upon analysing it we realise that this is a straight-forward decryption challenge. we have all that's required for decryption and we just need to reverse all the encryption logic.
## Computing the Shared Secret
observe that all we need to know for the AES decryption is the shared secret. to compute this we need the `x-`coordinate of the `new_point`. since we know the `start_point` and the scalar multiplier as well, this is an easy task. here's a sage script that computes this 
```py
from sage.all import *
from Crypto.Util.number import *

# y^2 = x**3 + 13x + 245 % 335135809459196851603485825030548860907
p = 335135809459196851603485825030548860907
Fp = GF(p)
E = EllipticCurve(Fp, [13, 245])

P = E((14592775108451646097, 237729200841118959448447480561827799984))
Q = P * 1337 

print(Q)
```
the result is 
```shell
fooker@fooker:~/byuctf-2024/crypto/times$ python3 solve.sage
(130102914376597655583988556541378621904 : 127059956561887163664745694619573305167 : 1)
```
thus we have `shared_secret = 130102914376597655583988556541378621904`
## AES Decryption
notice that the AES encryption mode used was `CBC` and therefore we require the `iv` that we already have anyway and now we know the `key` too. so we could stuff all the required parameters into the decryption oracle to get the flag 
## Solve Script
```py
import hashlib
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from base64 import *
import os
from Crypto.Util.number import getPrime

shared_secret = 130102914376597655583988556541378621904 
ciphertext= b'SllGMo5gxalFG9g8j4KO0cIbXeub0CM2VAWzXo3nbIxMqy1Hl4f+dGwhM9sm793NikYA0EjxvFyRMcU2tKj54Q=='
iv = b'MWkMvRmhFy2vAO9Be9Depw=='

ciphertext = b64decode(ciphertext)
iv = b64decode(iv)

#get AES key from shared secret
sha1 = hashlib.sha1()
sha1.update(str(shared_secret).encode('ascii'))
key = sha1.digest()[:16]

# plaintext = pad(plaintext.encode('ascii'), AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

print(plaintext)
```
and we get the flag
```bash
fooker@fooker:~/byuctf-2024/crypto/times$ python3 solve.py
b'byuctf{mult1pl1c4t10n_just_g0t_s0_much_m0r3_c0mpl1c4t3d}\x08\x08\x08\x08\x08\x08\x08\x08'
```