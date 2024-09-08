Policy based Modbus TCP security framework on P4 (BMv2). Pipeline performs following sequence of checks :
Flow check -> Length check -> Function code check -> Modbus Request DoS defense -> Modbus Response delay check

Pre-requisites:
- bmv2 / p4c compiler
- gRPC
- pypi
- mininet

To compile .p4 file and generate JSON

p4c --target bmv2 --arch v1model --std p4-16 modbus.p4

This generates modbus.json which can be used as argument while instantiating mininet instance

sudo python3 topo.py --behavioral-exe simple_switch --json modbus.json
