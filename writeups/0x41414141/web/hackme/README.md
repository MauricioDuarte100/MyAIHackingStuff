# Hackme
We were given the challenge text:
```
can you please just hack me, I will execute all your commands but only 4 chars in length

EU instance

US instance

author: pop_eax
```

I personally would say that this is closer to a misc challenge than a web, but it was still fun! The website was pretty much just a web interface for a shell, so I made a (way too advanced) Python script to interact with it.
```py
import requests

servers = {
    'eu': 'http://207.180.200.166:8000/',
    'us': 'http://45.134.3.200:8000/'
}

server = input(f'EU or US?\n> ').lower()

url = servers[server]

while True:
    cmd = input('$ ')

    if cmd == 'reset':
        res = requests.get(f'{url}/?reset=1').text
    elif cmd == 'q':
        quit()
    else:
        res = requests.get(f'{url}/?cmd={cmd}').text
    print(res)
```

Our goal was to view the contents of the flag in `/flag.txt`. In typical me style, I overcomplicated everything. I spent probably a day trying to craft an exploit that allowed me to curl my own server for a file containg `cat /flag.txt`, but of course curl didn't work, and I had to try again. A lot of my earlier testing included `*`, so I had done some researching on how exactly it works. After a bit of thinking, I realized I could create a file titled `cat`, and if it was the only file in the directory I could simply type `*`, and it would be replaced by `cat`. The final solution was a simple 2 lines: `>cat` (creates the file) and `* /f*` (cats /flag.txt). The result was `flag{ju57_g0tt@_5pl1t_Em3012}`.