# Missing Flavortext
### Made by: BrownieInMotion

Challenge text:
```
Hmm, it looks like there's no flavortext here. Can you try and find it?

missing-flavortext.dicec.tf
```
We were also given the file [index.js](index.js)

The website is a simple login, with nothing more to it. I try a simple SQL injection, but it doesn't work. In the [index.js](index.js) file we see that it checks if the username or password request field contain a `'`, and if it does it returns. I tried a lot of different things at first, but with no results. 

I notice that app uses the bodyParser middlware, but with the `extended` argument set to true. Even though I don't know what the argument does, it still stood out as a bit unnecessary and CTF-like. After a quick search I found out that if `extended` is enabled the requests are parsed using [qs](https://www.npmjs.com/package/qs). One of the primary uses of `qs` seems to be the ability to parse objects. Around this point I realized that `.includes` probably doesn't work on objects, so I tried sending a payload where the password was an object, I used Python for this.
```py
import requests

payload = {
    "username": "admin",
    "password": [
        [
            "a",
            "' OR 1=1;--"
        ]
    ]
}

print(requests.post('https://missing-flavortext.dicec.tf/login', data=payload).text)
```
It worked! `.includes` didn't see the single quote, but when converted to a string it simply became `a' OR 1=1;--`. The response included the flag `dice{sq1i_d03sn7_3v3n_3x1s7_4nym0r3}`.