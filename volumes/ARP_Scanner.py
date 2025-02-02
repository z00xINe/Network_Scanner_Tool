#! /usr/bin/env python3

from scapy.all import *

def networkDiscovery(subnet):
  answered_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=False)[0]

  print("Active devices on the network:")

  for sent, received in answered_list:
    print(f"'IP': {received.psrc} \t 'MAC': {received.hwsrc}")


subnet = input("Enter subnet of network: ")
networkDiscovery(subnet)