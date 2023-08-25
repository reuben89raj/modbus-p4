import socket
import binascii

INTERFACE_NAME = "eth0"  # replace with the name of your interface
HEX_STRING = "0800000001000800000001110800450000348584400080065e3e0a0001010a0002010a1201f66197f18f70f1ad245018fae7168000000000000000060a0800040000"

# Convert hex string to bytes
packet_data = binascii.unhexlify(HEX_STRING)

# Create a raw socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

# Bind to a specific interface
s.bind((INTERFACE_NAME, 0))

# Send the packet
s.send(packet_data)

s.close()

print(f"Packet sent through {INTERFACE_NAME}")

