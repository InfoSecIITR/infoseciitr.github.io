from pwn import *

r = remote('challs.bcactf.com',31704)
# context.log_level = 'debug'

r.recvuntil(b': ')
r.sendline(b'\x00')
r.recvuntil(b'n = ')
n = int(r.recvline().decode().strip())
for i in range(2):
    r.recvuntil(b': ')
    r.sendline(b'\x00')
r.recvuntil(b') ')
r.sendline(b'yes')
r.recvuntil(b': ')
c = int(r.recvline().decode().strip())
r.recvuntil(b'n = ')
n2 = int(r.recvline().decode().strip())

import math
p = math.gcd(n,n2)
r = n2//p
phi = n2-p-r+1
e = 65537
d = pow(e,-1,phi)
m = pow(c,d,n2)

from Crypto.Util.number import *
print(long_to_bytes(m).decode())