# Secure enclave
We were given the challenge text:
```
I just found this dope smart contract, you just give it a secret and it hides it on the ethereum network.

address: 0x9B0780E30442df1A00C6de19237a43d4404C5237

author: pop_eax
```

Along with the file [alerted.sol](alerted.sol).

This time the flag was encrypted in the contract, so we couldn't see it without reversing it (which of course isn't intended). To make a change on the blockchain (to store the secret text), a transaction has to be sent. Knowing this, we can assume that the flag has been sent as input data to the contract. The [5th transaction](https://rinkeby.etherscan.io/tx/0x3e3498a9bbb97500f1cfb03fc4ce69aa2eddc475aaff8705414275065b8cb1ea) after the contract creation included the flag. All we have to do to see the flag is convert the hex input to UTF-8, giving us the flag: `flag{3v3ryth1ng_1s_BACKD00R3D_0020}`.

The intended solution was to get all the event entries of the `pushhh` event, as all secrets were broadcasted. 