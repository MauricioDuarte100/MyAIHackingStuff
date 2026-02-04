# Phasestream 1

Challenge text:
```
The aliens are trying to build a secure cipher to encrypt all our games called "PhaseStream". They've heard that stream ciphers are pretty good. The aliens have learned of the XOR operation which is used to encrypt a plaintext with a key. They believe that XOR using a reapeted 5-byte key is enough to build a strong stream cipher. Such silly aliens! Here's a flag they encrypted this way earlier. Can you decrypt it (hint: what's the flag format?) 2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904
```

Since the XOR key is 5 bytes long, and we know the 5 first characters of the flag (`CHTB{`}). If we XOR the 5 first bytes of the encrypted flag (`2e313f2702`) with `CHTB{`, the result is `mykey`. If we XOR the encrypted flag with `mykey`, we get the the flag; `CHTB{u51ng_kn0wn_pl41nt3xt}`