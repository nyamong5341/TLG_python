#!/usr/bin/python3
from scapy.all import *
#import netifaces



#sniffing packets

from scapy.all import *

def main():
    try:
        # Capture 10 packets
        packets = sniff(count=10)
        
        # Print captured packets
        print(packets)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

