from pwn import *

r = remote('challs.bcactf.com',31452)
# context.log_level = 'debug'

r.recvuntil(b')\n')
ct1,n1 = eval(r.recvline().decode().strip())
r.recvuntil(b') ')
r.sendline(b'n')
ct2,n2 = eval(r.recvline().decode().strip())
r.recvuntil(b') ')
r.sendline(b'n')
ct3,n3 = eval(r.recvline().decode().strip())
r.recvuntil(b') ')
r.sendline(b'y')

from sympy.ntheory.modular import crt
m_cube = crt([n1,n2,n3] , [ct1,ct2,ct3])[0]

from gmpy2 import iroot
m = int(iroot(m_cube,3)[0])

from Crypto.Util.number import *
print(long_to_bytes(m).decode())