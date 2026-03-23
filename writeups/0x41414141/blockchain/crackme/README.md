# Crackme.sol
We were given the challenge text:
```
the fact that everything can be turned into a crackme is so cool

address: SECRET_REDACTED_BY_ANTIGRAVITYBE

author: notforsale
```

Along with the file [chall.sol](chall.sol).

This time OSINTing the flag would be a bit harder, so I tried to go for a more intended solution. I assume we have to call the `gib_flag` function, which takes 3 arguments (uint `arg1`, string memory `arg2`, uint `arg3`).

By looking at the function we see that `(arg1 ^ 0x70) == 20` has to be true. Due to how XOR works, we can simply XOR `0x70` with `20` to get `arg1`; `0x70 ^ 20 = 100`. `arg1` then has to be `100`.

The next argument is a string, we see that `decrypt(arg2)` has to be the same as `offshift ftw`. The goal of the challenge is of course to revere the decrypt function (especially the assembly part), to find the input that equals `offshift ftw`. However, I didn't have time for this. Even though you only have to call the `gib_flag` function to get the output (since you don't write anything to the blockchain), I hoped that someone had made a transaction with the correct input data anyways, and I was correct! I clicked on a random transaction and decoded the input,  ignoring the garbage data I saw the string `evvixyvj vjm` (which is ROT10 of `offshift ftw`). I assumed this was the correct data for `arg2`.

Finally I had `arg3`. The function first checks if `arg3` is larger than 0, but later in the code we see that `arg3 + 1` should be less than `1`. This should of course be impossible, but as also hinted by the comment, this can be achieved by an overflow. Since the Solidity `uint` type is 256 bit, `arg3` has to be the highest possible 256 bit unsigned number, which is 2<sup>256</sup>-1, or `SECRET_REDACTED_BY_ANTIGRAVITY69984665640564039457584007913129639935`. 

Now yet another problem appeared. I had all then correct function arguments, but how would I call the function? I did some googling, and came across [web3](https://pypi.org/project/web3/), `A Python library for interacting with Ethereum`. After a little documentation reading, I got working code that succesfully called the contract's function.

```py
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

w3 = Web3(Web3.HTTPProvider('https://rinkeby.infura.io/v3/API_KEY')) # Instead of running a local node to connect to the Rinkeby network, I used https://infura.io/

w3.middleware_onion.inject(geth_poa_middleware, layer=0) # Some stuff StackOverflow told me to add after I got errors

contract_address = 'SECRET_REDACTED_BY_ANTIGRAVITYBE' # The address of the contract

# I used http://remix.ethereum.org/ to generate the ABI for me from the source code, this allows web3 to know what kind of functions exist in the contract, what those function return, etc.
abi = '[{"inputs":[{"internalType":"uint256","name":"arg1","type":"uint256"},{"internalType":"string","name":"arg2","type":"string"},{"internalType":"uint256","name":"arg3","type":"uint256"}],"name":"gib_flag","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]'

contract = w3.eth.contract(contract_address, abi=abi)

print(contract.functions.gib_flag(100, 'evvixyvj vjm', (pow(2, 256) - 1)).call()) # I then called the function using my arguments, and printed the results
```

I hoped this would print the flag, but apparently I was doing something wrong. I'm not sure if it's a library error or user error, but the expected output was a uint[] of the flag, however all I got was `67`. I tried changing the return type of `gib_flag` in the ABI for a while, but it just gave me errors. After a litte more thinking, I realized that the library probably received the raw data, and then attempted to parse this. In Visual Studio code I ctrl-clicked on `.call()`, and it took me to the function definition in the library. The `call` function returned the response of another function, `call_contract_function`. I went to the definition of this function as well, and I saw the variable `return_data`. I then simply added a print statement, and when I now ran my code it printed the raw response data. 

```
b'SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY0\x00\x00\x00\x00\x00\x00\x00@SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY00\x00\x00\x00_SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYx00\x00\x00\x00\x00_SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY00\x00\x00\x00@SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY\x00\x00\x00\x00\x00\x00_SECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITYSECRET_REDACTED_BY_ANTIGRAVITY\x00\x00\x00\x00\x00\x004'
```

I then removed all the nullbytes, `return_data.decode().replace('\x00', '')`, and the result was the flag: `flag{C0ngr@75_Y0u_CR@CK3D_m3854}`