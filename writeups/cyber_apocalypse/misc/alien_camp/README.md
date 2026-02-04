# Alien Camp

Challenge text:
```
The Ministry of Galactic Defense now accepts human applicants for their specialised warrior unit, in exchange for their debt to be erased. We do not want to subject our people to this training and to be used as pawns in their little games. We need you to answer 500 of their questions to pass their test and take them down from the inside.
```

After connecting to the challenge with netcat, there's a prompt with 2 options, one displays some variables, the other starts a test.
```
$ nc 138.68.187.25 31051
Alien camp 👾

1. ❓
2. Take test!
> 1
Here is a little help:

🌞 -> 73 🍨 -> 78 ❌ -> 62 🍪 -> 94 🔥 -> 6 ⛔ -> 35 🍧 -> 64 👺 -> 68 👾 -> 7 🦄 -> 90 

1. ❓
2. Take test!
> 2

You must answer 500 questions. You have only a few seconds for each question! Be fast! ⏰

Question 1:

🦄 - 🍪 + 🌞 + 🍪 * 🦄 * 🔥  = ?

Answer:
```

We have to send the answer to 500 math equations, where the variables are emoji names. I created a Python script to solve it.
```py
from pwn import remote

io = remote("138.68.187.25", 31051)

io.recvuntil("> ") # recieve until we get prompted for input
io.sendline("1") # send 1 to get the variables
io.recvline() # Here is a little help:
io.recvline() # \n 
emojis = io.recvlineS().split() # the line with the emoji values

# ['🌞', '->', '53', '🍨', '->', '83', '❌', '->', '10', '🍪', '->', '74', '🔥', '->', '39', '⛔', '->', '83', '🍧', '->', '3', '👺', '->', '49', '👾', '->', '90', '🦄', '->', '77']
print(emojis)

vals = {}

for x in range(0, len(emojis), 3):
    vals[emojis[x]] = emojis[x+2]

# {'🌞': '53', '🍨': '83', '❌': '10', '🍪': '74', '🔥': '39', '⛔': '83', '🍧': '3', '👺': '49', '👾': '90', '🦄': '77'}
print(vals)

io.recvuntil("> ") # recieve until we get input
io.sendline("2") # start the test

for _ in range(500):
    io.recvuntil(":\n\n") # recieve until the equation
    eq = io.recvlineS().split(" = ")[0] # the equation

    # 🔥 * 👾 - ❌ - 🌞 * 🦄 - 🦄 - 👾
    print(eq)

    # replace the emojis in the equation with their respective integer values
    for x in vals:
        eq = eq.replace(x, vals[x])
    
    # 84 * 88 - 56 - 65 * 89 - 89 - 88 
    print(eq)

    # blindly eval the equation, and send the answer to the server
    ans = str(eval(eq))

    io.recvuntil(": ")
    io.sendline(ans)
io.interactive()
```

After letting the script run, we get the flag.
```
Congratulations! 🎉
You are one of us now! 😎!
Here is a 🎁 for you: CHTB{3v3n_4l13n5_u53_3m0j15_t0_c0mmun1c4t3}
```