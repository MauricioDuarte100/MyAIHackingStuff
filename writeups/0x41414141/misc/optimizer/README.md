# Optimizer
We were given the challenge text:
```
EU instance: 207.180.200.166 9660

US instance: 45.134.3.200 9660

author: pop_eax
```

Upon connecting to the socket using netcat, we got the message
```
you will be given a number of problems give me the least number of moves to solve them
level 1: tower of hanoi
```
followed by a list of numbers. This challenge was a bit hard to understand at first, but after a bit of trial and error I figured out what it wanted. [According to Wikipedia](https://en.wikipedia.org/wiki/Tower_of_Hanoi#Solution), the miminum number of solves for a TOH is 2<sup>n</sup>-1., where `n` is the amount of disks, or in this instance, the length of the integer array. After connecting to the socket via Python and parsing the input, the answer was a simple oneliner `current_answer = str(pow(2, len(arr))-1).encode()`., where `arr` is the list we received as input. 

After letting the script solve quite a few of these, it hit level 2.
```
level 2 : merge sort, give me the count of inversions
```
After trying to learn a bit, I decided to go the easy way instead. [This website](https://www.geeksforgeeks.org/counting-inversions/) has copy-paste ready code for finding the inversion count of a merge sort. I copied this into a function, and it worked.

There were no more levels after this, and I received the flag: `flag{g077a_0pt1m1ze_3m_@ll}`

Since you had to solve a lot for each level, I created a Python script to interact with the socket. (I was expecting more than 2 levels, so it's a bit unnecessary long).
```py
import ast
import re
import socket

current_answer = ''
level = 1

s = socket.socket()
s.connect(('207.180.200.166', 9660)) # connects to the web socket 

def level_1(arr):
    global current_answer
    current_answer = str(pow(2, len(arr))-1).encode() # returns the encoded answer for level 1, Tower of Hanoi 

def level_2(arr):
    global current_answer

    n = len(arr)
    inv_count = 0
    for i in range(n): 
        for j in range(i + 1, n): 
            if (arr[i] > arr[j]): 
                inv_count += 1

    current_answer = str(inv_count).encode() # returns the encoded answer for level 2, merge sort inversions

while True: # continouly read data from socket
    received = s.recv(2048).decode()
    print(received)

    if 'wrong' in received or 'flag' in received:
        quit()
    
    if 'level 1' in received:
        level = 1
    if 'level 2' in received:
        level = 2
        
    if level == 1:
        try:
            inp = re.findall(r'\[[0-9, ]+\]', received)[0] # regex to only get the list itself from the data
            inp = ast.literal_eval(inp) # converts the string list to an actual list
            level_1(inp)
        except IndexError:
            pass
    if level == 2:
        try:
            inp = re.findall(r'\[[0-9, ]+\]', received)[0]
            inp = ast.literal_eval(inp)
            level_2(inp)
        except IndexError:
            pass
    
    if '>' in received: # sends the answer to the socket
        print(current_answer.decode())
        s.send(current_answer)
```