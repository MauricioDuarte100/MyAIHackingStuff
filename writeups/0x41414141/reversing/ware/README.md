# Ware
We were given the challenge text:
```
My plaintext has been encrypted by an innocent friend of mine while playing around cryptographic libraries, can you help me to recover the plaintext , remembers it's just numbers and there's a space between some numbers which you need to remove the space and submit the recovered plain text as a flag.

Author: ElementalX
```

Along with the file [skidw4re](skidw4re).

When I first opened the file, the disassembled code that I saw was *scary*. After looking at the strings of the file, I noticed that the executable was packed with [UPX](https://upx.github.io/). I downloaded UPX and unpacked the binary, this time the assembly was a lot nicer to look at. For this challenge I had discovered [Binary Ninja](https://binary.ninja/), and I'm really glad I did. After looking around in the code for probably 2 minutes, BN pretty much handed me the flag. If we remember back to the challenge text, `it's just numbers and there's a space between`. In the function `main.encryptFinal` there's a call to the function `main.encryptAES`. Right before the function call, a string is loaded into `ebx` from memory (`data_812ce40`).
```
mov     ebx, data_812ce40  {"321174068998067 98980909"}
```
Next to the instruction, BN kindly displays the string value; `321174068998067 98980909`. The flag is `flag{32117406899806798980909}`.