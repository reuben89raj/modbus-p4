import socket
import binascii

INTERFACE_NAME = "eth0"  # replace with the name of your interface
HEX_STRING = "0004000100060002b3ce7051080045000031ffe640008006e3de0a0002010a00010101f60a1270f1ad246197f19b5018ffe705fe00000000000000030a880bFFFF"

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
