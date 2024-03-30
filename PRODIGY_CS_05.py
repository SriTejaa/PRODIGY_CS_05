# Import necessary modules
from scapy.all import *

# Define IP address
IP = "192.168.1.1"

# Define a raw packet
Raw = b'\x00\x01\x02\x03\x04'

# Define a sniffing function
def sniff_packets():
    print("Sniffing packets...")
    sniff(count=5, filter="tcp", prn=lambda x: x.summary())

# Main function
def main():
    print("Starting program...")

    # Perform some operations with IP, Raw, and sniff
    print("IP address:", IP)
    print("Raw packet:", Raw)
    sniff_packets()

    print("Program completed successfully.")

if __name__ == "__main__":
    main()
