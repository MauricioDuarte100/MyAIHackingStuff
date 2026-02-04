# MiniSTRyplace

Challenge text:
```
Let's read this website in the language of Alines. Or maybe not?
```
Along with the [source code](web_ministryplace).

The website was quite simple, with buttons to switch between two languages. The different languages were chose by the get parameter `lang`, and it just includes a file. The flag is two folders up, so I tried `/?lang=../../flag`, which didn't work. As we see in the source code, `../` is removed. However, this means that you can instead send in `/?lang=..././..././flag`, as after removing `../` it will become `/?lang=../../flag`, and you get the flag.