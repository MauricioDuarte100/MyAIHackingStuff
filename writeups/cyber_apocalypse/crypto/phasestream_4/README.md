# Phasestream 4

Challenge text:
```
The aliens saw us break PhaseStream 3 and have proposed a quick fix to protect their new cipher.
```
Along with the files [output.txt](output.txt)

```
2d0fb3a56aa66e1e44cffc97f3a2e030feab144124e73c76d5d22f6ce01c46e73a50b0edc1a2bd243f9578b745438b00720870e3118194cbb438149e3cc9c0844d640ecdb1e71754c24bf43bf3fd0f9719f74c7179b6816e687fa576abad1955
2767868b7ebb7f4c42cfffa6ffbfb03bf3b8097936ae3c76ef803d76e11546947157bcea9599f826338807b55655a05666446df20c8e9387b004129e10d18e9f526f71cabcf21b48965ae36fcfee1e820cf1076f65
```
and [phasestream4.py](phasestream4.py)
```py
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

KEY = os.urandom(16)


def encrypt(plaintext):
    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()


with open('test_quote.txt', 'rb') as f:
    test_quote = f.read().strip()
print(encrypt(test_quote))

with open('flag.txt', 'rb') as f:
    flag = f.read().strip()
print(encrypt(flag))
```

The Python script reads input from 2 files, and then encrypts them using AES CTR (counter) mode. AES CTR mode is vulnerable to a crib-dragging attack if the IV (counter + key) is reused. As we see in the above Python code, it is. By XORing two encrypted messages encrypted using the same IV with the plaintext of one of them, you can get the plaintext of the other encrypted message: `enc1 ^ enc2 ^ pt1 = pt2`. The only problem is the fact that we don't know the full plaintext of either encrypted message.

We can assume that the first 5 bytes of the last encrypted message is `CHTB{`. By XORIng `enc1[:5] ^ enc2[:5] ^ CHTB{` we get the result `I alo`. Since the file name of the first encrypted message is `test_quote` I found a top 100 list of famous quotes, and ctrl + f'ed for `I alo`. The quote `I alone cannot change the world, but I can cast a stone across the water to create many ripples.` by Mother Teresa came up, so I assume this is the plaintext for the first encrypted message.

I finally solved the challenge using this script:
```py
enc = open("output.txt", "r").read().split("\n") # list of the 2 encrypted strings
enc = [bytes.fromhex(x) for x in enc] # converted from hex to bytes

out = b""
pt = b"I alone cannot change the world, but I can cast a stone across the water to create many ripples." # assume this is the plaintext for the first encrypted string

for x in range(len(enc[1])):
    out += bytes([enc[0][x] ^ enc[1][x] ^ pt[x]]) # XOR character at position "x" of both encrypted strings with the plaintext

print(out)
```

This gives us the flag; `CHTB{stream_ciphers_with_reused_keystreams_are_vulnerable_to_known_plaintext_attacks}`.