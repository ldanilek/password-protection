from random import random

fileName = raw_input("file name: ")
characters = input("char count: ")

file = open(fileName, "w")


meta = []
# add in the printable characters
for i in range(32, 127):
    meta += [str(chr(i))]

for i in range(characters):
    file.write(meta[int(random() * len(meta))])
    file.write("\n")

file.close()

