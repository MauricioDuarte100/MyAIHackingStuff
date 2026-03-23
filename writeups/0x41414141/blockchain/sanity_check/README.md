# Sanity Check
We were given the challenge text:
```
aren't you tired of the lame read the rules flag ?

that's why over at this CTF the flag is on the blockchain over at this address SECRET_REDACTED_BY_ANTIGRAVITY2d

network : Rinkeby
```

Along with the file [chall.sol](chall.sol) which is a Solidity file, I didn't know how what to do with it though, so I ignored it.

After a short bit of searching I [found the contract on the Rinkeby testnet](https://rinkeby.etherscan.SECRET_REDACTED_BY_ANTIGRAVITY7c1a6da82032d). I then went to the [contract code and decompiled it](https://rinkeby.etherscan.io/bytecode-decompiler?SECRET_REDACTED_BY_ANTIGRAVITY032d). Due to the public nature of the blockchain we could see the flag from the contract's source code: `flag{1t_1s_jus7_th3_st@rt}`.