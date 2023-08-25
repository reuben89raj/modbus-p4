def get_hosts_connected_to_switch_with_ports_and_routers(links):
  """
  Get hosts connected to each switch, along with the ports for each switch, and the ports connected to routers.

  Args:
    links: A list of links, where each link is a tuple of two strings:
      (device1, device2)

  Returns:
    A dictionary mapping switches to a list of tuples, where each tuple is a host and a port.
  """

  # Create a dictionary mapping switch names to a list of tuples. The dictionary is initialized with an empty list for each switch.
  hosts_connected_to_switch_with_ports_and_routers = {}
  for device1, device2 in links:
    if device1.startswith("h"):
      switch = device2.split("-")[0]
      if switch not in hosts_connected_to_switch_with_ports_and_routers:
        hosts_connected_to_switch_with_ports_and_routers[switch] = []
      hosts_connected_to_switch_with_ports_and_routers[switch].append((device1, device2.split("-")[1]))
    elif device1.startswith("r"):
      switch = device2.split("-")[0]
      if switch not in hosts_connected_to_switch_with_ports_and_routers:
        hosts_connected_to_switch_with_ports_and_routers[switch] = []
      hosts_connected_to_switch_with_ports_and_routers[switch].append((device1, device2.split("-")[1]))

  # Create a dictionary mapping switch names to a list of ports that connect to end hosts starting with "h".
  hosts_connected_to_switch_ports = {}
  for switch, hosts in hosts_connected_to_switch_with_ports_and_routers.items():
    hosts_connected_to_switch_ports[switch] = []
    for host, port in hosts:
      if host.startswith("h"):
        hosts_connected_to_switch_ports[switch].append(port)

  # Create a dictionary mapping switch names to a list of ports that connect to routers.
  router_connected_to_switch_ports = {}
  for switch, hosts in hosts_connected_to_switch_with_ports_and_routers.items():
    router_connected_to_switch_ports[switch] = []
    for host, port in hosts:
      if host.startswith("r"):
        router_connected_to_switch_ports[switch].append(port)

  # Return the three dictionaries.
  return hosts_connected_to_switch_with_ports_and_routers, hosts_connected_to_switch_ports, router_connected_to_switch_ports

links = [
        ["hmaster", "s1-p1"], ["hrtu1", "s2-p1"], ["hrtu2", "s2-p2"], ["hrtu3", "s3-p1"], ["hrtu4", "s3-p2"],
        ["s1-p2", "r1-p1"], ["s2-p3", "r2-p1"], ["s3-p3", "r3-p1"],
        ["r1-p2", "r2-p3"], ["r2-p2", "r3-p3"], ["r3-p2", "r1-p3"]
    ]

hosts_connected_to_switch_with_ports_and_routers, hosts_connected_to_switch_ports, router_connected_to_switch_ports = get_hosts_connected_to_switch_with_ports_and_routers(links)
print("hosts_connected_to_switch_with_ports_and_routers :", hosts_connected_to_switch_with_ports_and_routers)
print("")
print("hosts_connected_to_switch_ports :", hosts_connected_to_switch_ports)
print("")
print("router_connected_to_switch_ports :", router_connected_to_switch_ports)
