#!/usr/bin/python3
import sys

if len(sys.argv) == 1:
    print("Give me a file")
    exit()

f = open(sys.argv[1], "r")
lines = f.readlines()
union = [] 

for line in lines: 
    if "gfn" in line:
        splitted_line = line.split()
        if splitted_line[1] not in union:
            union.append(splitted_line[1])
    
print("\n".join(union))