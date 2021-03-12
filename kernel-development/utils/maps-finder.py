#!/usr/bin/python3
import sys

def usage():
    print("Easily find what you need from /proc/pid/maps !")
    print("Usage: maps-finder.py pid address")
    print("Example: ./maps-finder.py 8805 0x7fdde7ffb170")

def within(target, addr1, addr2):
    if target >= addr1 and target <= addr2:
        return True
    return False

def main():
    if len(sys.argv) != 3:
        usage()
        exit()

    pid = sys.argv[1]
    address = int(sys.argv[2], 16)
    filename = "/proc/{}/maps".format(pid)

    try: 
        f = open(filename, "r")
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