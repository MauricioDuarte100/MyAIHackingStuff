# Phasestream 2

Challenge text:
```
The aliens have learned of a new concept called "security by obscurity". Fortunately for us they think it is a great idea and not a description of a common mistake. We've intercepted some alien comms and think they are XORing flags with a single-byte key and hiding the result inside 9999 lines of random data, Can you find the flag?
```
Along with the file [output.txt](output.txt).

This time we have a file with 10000 lines, one of which is the flag XORed with an unknown 1 byte value. We can solve this by XORing all 10000 lines with all 255 1-byte values:

```py
lines = open("output.txt", "r").read().split("\n") # make a list with all the hex values from the output.txt file
lines = [bytes.fromhex(x) for x in lines] # convert hex to bytes

for xor_byte in range(0x100): # try all bytes in the range 0x00 to 0xff
    for line in lines: # go through every line
        xored = bytes([c^xor_byte for c in line]) # xor each byte of the current line with the current xor byte
        if b"CHTB" in xored:
            print(xored)
```
Not long after running this we get the flag.