from pwn import *
from Crypto.Util.number import *

r = remote('challs.bcactf.com',31100)
context.log_level = 'debug'
r.recvuntil(b':\n')
ct = r.recvline().decode().strip()
payload = b'0'*(len(ct)//2)
xor2 = int.from_bytes(payload,'big')
ct = int(ct,16)
r.recvuntil(b':\n')
r.sendline(payload)
r.recvuntil(b':\n')
xor = int(r.recvline().decode().strip(),16)
pt = ct^xor^xor2
r.sendline(long_to_bytes(pt))
r.interactive()