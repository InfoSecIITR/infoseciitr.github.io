m = '011000001011010000111000011000111110011000111100011101001100001001100111011111110110011110010100011100010111011011111001010011011011010100011010001010011110010110010000001110111010001000011100011100011100010011111101010101101011110000110010001101100011011010100011001001010010001011011111011110000010001101100110010000110011011101110101010010111000011100011001010100011001001000111000001101010001011000100111010011000001011100011111111101010111010001001000001101000000001101011100010101101010101011011110011010100010010010010011010101010101010000010000001011011100011000011010010000111110001110011111011100011101010110001010010100100111001110011100011010101000011000101010001000101001001100011101111101100010010011100000010101111010011101101000011100100101001001000001010001111111010001001101111110100101011111001100'
m = [m[i:i+12] for i in range(0,len(m),12)]
m = [[i[:8],i[8:]] for i in m]

def find_leftmost_set_bit(plaintext):
    pos = 0
    while plaintext > 0:
        plaintext = plaintext >> 1
        pos += 1
    return pos

def encrypt(plaintext: str):
    enc_plaintext = ""

    for letter in plaintext:
        cp = int("10011", 2)
        cp_length = cp.bit_length()
        bin_letter, rem = ord(letter), ord(letter) * 2**(cp_length - 1)
        while (rem.bit_length() >= cp_length):
            first_pos = find_leftmost_set_bit(rem)
            rem = rem ^ (cp << (first_pos - cp_length))
        enc_plaintext += format(bin_letter, "08b") + format(rem, "0" + f"{cp_length - 1}" + "b")
        
    return enc_plaintext

flag = ''
for i,j in m:
    found = False
    for xor in range(8):
        k = encrypt(chr(int(i,2)^pow(2,xor)))
        if (j==k[-4:]):
            flag+=chr(int(i,2)^pow(2,xor))
            found=True
            break
    if found:
        continue
    for xor in range(4):
        k = encrypt(chr(int(i,2)))
        if ((int(j,2)^pow(2,xor))==int(k[-4:],2)):
            flag+=chr(int(i,2))
            break

print(flag)