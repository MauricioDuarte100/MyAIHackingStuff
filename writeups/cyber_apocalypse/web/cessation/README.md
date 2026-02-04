# Cessation

Challenge text:
```
Enemy forces are using a stealthy device to penetrate into our country. We've identified its origin and its time cessate their strength and defend our country from the attack.
```
Along with a [remap config file](remap.config).

The remap file had the contents:
```
regex_map http://.*/shutdown http://127.0.0.1/403
regex_map http://.*/ http://127.0.0.1/
```
which means it redirects any request to `http://.*/shutdown` (where `.*` means anything in regex) to a 403 page.

You can quite easily bypass this by sending the GET request `GET /./shutdown HTTP/1.1`. The regex won't match, and you'll get the flag. 

Note:
If you just try to go to `http://206.189.121.131:30870/./shutdown` in your browser, it'll ignore the `./`, and still send you to a 403 page. You'll need to send a raw request instead, by using for example burp repeater or netcat.