#!/usr/bin/python3
# Was using this as a pointer initially
# https://medium.com/@info_82002/python-for-network-traffic-analysis-2386b8d6144e
# Then switched to
# https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html
# Howwever, that was mostly just a kickstart.
# Most of the information here came from:
# https://scapy.readthedocs.io/en/latest/index.html
# Namely
# https://scapy.readthedocs.io/en/latest/usage.html

# Also helpful:
# https://www.ietf.org/rfc/rfc1002.txt

# Description:
# This is a file designed to analyze broadcast messages sent (to your device)

from scapy.all import *
import re

macs = {} # Table mapping OUIs to their respective corperations

countsSent = {} # Packets from cards with XXX corp with XXX OUI
countsRecv = {} # Packets to cards with XXX corp with XXX OUI

arpTable = {} # The recovered ARP table
inferredConnections = {} # Connections inferred from ARP requests

# 
items = set()

# Downloaded from
# https://standards-oui.ieee.org/oui/oui.txt
with open("oui.txt", "r") as oui:
    for l in oui.readlines():
        if "(base 16)" in l:
            macs[l[:6]] = re.compile("\\(base 16\\)[^A-Za-z0-9]*(.+)$").search(l).group(1)


# Get rid of colons in the given mac address, and get the first six characters,
# so that we can match them to the OUI list that we downloaded
def fixupMAC(addr):
    return addr.replace(":", "").upper()[:6]

# Check the given MAC against our OUI list,
# and record its presence in the given map
def recordMAC(addr, d):
    mac = fixupMAC(addr)
    if not mac in macs:
        name="Unknown-%s" % mac
    else:
        name="%s-%s" % (macs[mac], mac)
    if not name in d:
        d[name] = 0
    d[name] += 1

# This, or rdpcap - not really sure what the difference is.
# I at first thought it buffered it, but nope.
pkts = sniff(offline="catcat.pcapng")

for p in pkts:
    # Record the sender and recieving macs
    recordMAC(p.src, countsSent)
    recordMAC(p.dst, countsRecv)
    if p.haslayer(ARP):
        # If this is an ARP request
        arp = p[ARP]
        if arp.op == 1:
            # request
            inferredConnections[arp.psrc] = arp.pdst
        elif arp.op == 2:
            # response (this would be from us)
            arpTable[arp.psrc] = arp.hwsrc
        else:
            # More like, "I didn't read the RFC"
            print("Err: malformed ARP packet?")
    elif p.haslayer(NBNSQueryRequest):
        # NetBIOS Name Service
        # I think this has something to do with network shares
        # the acryonym "SMB" comes to mind
        # ...
        # The name is encoded in some funky format, and I don't feel like
        # figuring it out right now.
        # See 4.1 NAME FORMAT
        # https://www.ietf.org/rfc/rfc1002.txt
        # Fortunately, it seems that string conversion works
        name = str(p[NBNSQueryRequest].QUESTION_NAME)
        # Removes python-added trash
        name = name[2:-1]
        items.add(name)


for k in countsSent:
    print("Packets from %s: %i" % (k, countsSent[k]))
for k in countsRecv:
    print("Packets to %s: %i" % (k, countsRecv[k]))

print("Recovered ARP table:")

for k in arpTable:
    print("%s -> %s" % (k, arpTable[k]))

print("Connections assumed from ARP request history:")

for k in inferredConnections:
    print("%s -> %s" % (k, inferredConnections[k]))

print("Devices names discovered from NetBIOS requests:")

for n in items:
    print("%s" % (n))

