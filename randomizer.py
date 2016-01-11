# handy little program to create random files of printable characters

from random import random

fileName = raw_input("file name: ")
characters = input("char count: ")

file = open(fileName, "w")

minChar = 32
maxChar = 126

minChar = 97
maxChar = 100

meta = []
# add in the printable characters
for i in range(minChar, maxChar+1):
    meta += [str(chr(i))]

for i in range(characters):
    file.write(meta[int(random() * len(meta))])

file.close()

