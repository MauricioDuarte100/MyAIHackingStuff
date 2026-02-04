from PIL import Image

test = open("clean_exported", "r").read().split("\n\n\n") # read the exported bits, split every 128th line(when it hits a divider; 3 newlines)
test = [x.split("\n") for x in test if len(x) != 8] # only keep the chunks, and not the seperators

for x in range(len(test)//8): # each image consits of 8 chunks
    oof = test[x*8:] # the current 8 chunks for the image

    colors = bytes([])

    # i struggled a bit with getting the bits in the correct order, this code is really not good nor intuitive, but it works!
    for a in range(8): # iterate through every chunk
        for b in range(7, -1, -1): # iterate through every bit (backwards)
            for c in range(128): # iterate through every column
                bit = oof[a][c][b] # the current bit
                if bit == "0": # convert the bit to RGB values for the image
                    colors += b"\x00"*3 # i didnt remember how to do it BW, so i just created RGB values...
                else:
                    colors += b"\xff"*3 # i didnt remember how to do it BW, so i just created RGB values...


    img = Image.frombytes("RGB", (128, 64), colors) # create a 128*64 image from the bits
    img.save(f"imgs/{x}.png") # save the image