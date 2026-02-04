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