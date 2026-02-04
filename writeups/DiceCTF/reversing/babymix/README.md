# Babymix
### Made by: mmaekr

Challenge text:
```
Just the right mix of characters will lead you to the flag :)
```
We were also given the file [babymix](babymix).

I opened the file Ghidra, and it was a relatively simple program. It took user input and ran this through some very simple checks. The checks were pretty much just preforming different mathematical operations on different parts of the input string and checking if they match a value. This would be very simple to reverse, if it wasn't for the fact that there were *28* of these checks. 

I was defintely not going to write down all checks in Python, so I went looking for an automated solution instead. A teammate of mine had talked about [angr](https://angr.io/) for reversing before, so I had a look at it. After quickly browsing through some [examples](https://github.com/angr/angr-doc/tree/master/examples), the [simulation manager docs](https://docs.angr.io/core-concepts/pathgroups), [program state docs](https://docs.angr.io/core-concepts/states) and the [claripy docs](https://docs.angr.io/advanced-topics/claripy) I made a nice script that solved it for me.

```py
import angr, claripy

input_len = 22 # the checks never checked for more than 22 chars, so I assumed password was 22 long

proj = angr.Project('babymix') # import the binary

stdin = claripy.BVS('flag', 8 * input_len) # create a 22-byte byte vector: https://docs.angr.io/advanced-topics/claripy
state = proj.factory.entry_state(stdin=stdin) # https://docs.angr.io/core-concepts/states

for x in range(input_len):
    state.solver.add(stdin.get_byte(x) >= 33) # the input can be anywhere between 33 and 126 (the characters) in the ASCII table
    state.solver.add(stdin.get_byte(x) <= 126)

simgr = proj.factory.simulation_manager(state) # https://docs.angr.io/core-concepts/pathgroups

simgr.explore(find=lambda s: b'Correct' in s.posix.dumps(1)) # the program prints "Correct" when you get the correct password

print(simgr.found[0].posix.dumps(0).decode()) # input
print(simgr.found[0].posix.dumps(1).decode()) # output
```

After letting the script run for a while, angr kindly prints out the correct password, `m1x_it_4ll_t0geth3r!1!` and the output `Wrap password in dice{} for the flag :)`.