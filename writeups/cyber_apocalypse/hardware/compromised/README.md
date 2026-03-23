# Compromised

Challenge text:
```
An embedded device in our serial network exploited a misconfiguration which resulted in the compromisation of several of our slave devices in it, leaving the base camp exposed to intruders. We must find what alterations the device did over the network in order to revert them before its too late
```
We are given the file [compromised.sal](compromised.sal). From the [serial logs challenge](../serial_logs) we know we need to use [Saleae's Logic 2 software](https://support.saleae.com/logic-software/sw-download).

This time the communication is across 2 channels, so I assume it's the I2C protocol. By selecting this setting we get an output that looks something like this:
```
write to 0x34 ack data: 0x73 
write to 0x34 ack data: 0x65 
write to 0x34 ack data: 0x74 
write to 0x34 ack data: 0x5F 
write to 0x34 ack data: 0x6D 
write to 0x34 ack data: 0x61 
write to 0x2C ack data: 0x43 
write to 0x34 ack data: 0x78 
write to 0x2C ack data: 0x48 
write to 0x34 ack data: 0x5F 
write to 0x34 ack data: 0x6C 
write to 0x2C ack data: 0x54 
write to 0x34 ack data: 0x69 
write to 0x34 ack data: 0x6D 
write to 0x2C ack data: 0x42 
write to 0x2C ack data: 0x7B 
write to 0x34 ack data: 0x69 
write to 0x34 ack data: 0x74 

...
```

![Output data](i2c_data.png)

I copy and paste all the data into VS Code, and using some regex find and replace I get the hex string
```
SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY29742523204035256D647D5316
```
Which decodes to:
```
set_maCxH_lTimB{itn_tuo1:110_se73t_2mimn1_nli4mi70t_2to5:_1c0+.]<+/4~nr^_yz82Gb3b"4#kU_..4+J_5.
3M.2B1.4B.1dV_5. yS.5B7k3..1V.Qxm.!j.@`Q52yq)t%# @5%md}S.
```
It looks like 2 strings combined, and if we look at the original data, it seems to be communication between `0x34` and `0x2C`. By only keeping the data sent to `0x2C`, we get the flag:
```
SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY5F35793537336D21403532292340257D

CHTB{nu11_732m1n47025_c4n_8234k_4_532141_5y573m!@52)#@%}
```