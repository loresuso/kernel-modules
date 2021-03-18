#!/usr/bin/python3
import sys
import os

def usage():
    print("Easily find what you need from /proc/pid/maps !")

def within(target, addr1, addr2):
    if target >= addr1 and target <= addr2:
        return True
    return False

def main():
    if len(sys.argv) != 2:
        usage()
        exit()

    try:
        address = int(sys.argv[1], 16)
    except:
        print("Error")
        exit()
    
    path = "/proc/"
    maps = path + "{}/maps"
    comm = path + "{}/comm"
    dirs = os.listdir(path)
    pid = ""

    for dir in dirs:
        try:
            f = open(comm.format(dir), "r")
            line = f.readline()
            if "qemu" in line:
                pid = dir
                break
        except:
            continue

    if pid == "":
        exit()

    try: 
        f = open(maps.format(pid), "r")
        lines = f.readlines()
        for line in lines:
            fields = line.split()
            addresses = fields[0].split("-")
            addresses[0] = int(addresses[0], 16)
            addresses[1] = int(addresses[1], 16)
            if within(address, addresses[0], addresses[1]) == True:
                print(line)
                break
    except:
        print("Error")

if __name__ == "__main__":
    main() 