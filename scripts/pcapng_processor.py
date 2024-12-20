#SOURCES:
# Github Copilot for formatting a lot of the code. Github copilot did most of the docstrings as well.
# GENERAL
# https://www.freecodecamp.org/news/practical-regex-guide-with-real-life-examples/
# https://www.datacamp.com/community/tutorials/python-regular-expression-tutorial
# https://scapy.readthedocs.io/en/latest/usage.html
# scapy documentation: https://scapy.readthedocs.io/en/latest/
# https://codewithgolu.com/python/network-packet-analysis-with-scapy-a-beginner-s-guide/
# https://www.datacamp.com/tutorial/pandas-tutorial-dataframe-python
# https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.resample.html
# https://pandas.pydata.org/docs/user_guide/10min.html
# https://github.com/KimiNewt/pyshark

# for TLS https://stackoverflow.com/questions/51423507/how-to-extract-an-ssl-tls-message-using-scapy-and-python
# TLS handshake: https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.handshake.html

# For the weak ciphers:
# https://www.emagined.com/blog/how-to-fix-weak-ciphers-and-strengthen-your-data-security
# What code links to what cipher: https://www.baeldung.com/linux/list-tls-ssl-ciphers-clients
# and https://wiki.mozilla.org/Security/Cipher_Suites

# also this link https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4

# Identifying more weak ciphers : https://security.stackexchange.com/questions/78/what-cryptographic-algorithms-are-not-considered-secure


import csv
# import logging
# import re
import statistics
from collections import Counter#, defaultdict
# from datetime import datetime, timedelta
# from typing import List, Dict, Any

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import pyshark
import seaborn as sns
from scapy.layers.l2 import ARP, Ether
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm

# Scapy imports
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
#from scapy.layers.http import HTTP
from scapy.layers.tls.all import *
#from pyshark import *


# Set up logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
#
# # Set the style for all plots
# #plt.style.use('seaborn-darkgrid')
# sns.set_palette("deep")
# plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica', 'sans-serif']
# plt.rcParams['font.size'] = 12
# plt.rcParams['axes.labelsize'] = 14
# plt.rcParams['axes.titlesize'] = 16
# plt.rcParams['xtick.labelsize'] = 12
# plt.rcParams['ytick.labelsize'] = 12



warnings.filterwarnings("ignore", message="TLS cipher suite not usable.*")

# Constants
WEAK_CIPHERS = [
    'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'SHA-1', 'RSA'
]

TLS_CIPHER_SUITES = {
    0x0000: 'TLS_NULL_WITH_NULL_NULL',
    0x0001: 'TLS_RSA_WITH_NULL_MD5',
    0x0002: 'TLS_RSA_WITH_NULL_SHA',
    0x0003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
    0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
    0x0006: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
    0x0007: 'TLS_RSA_WITH_IDEA_CBC_SHA',
    0x0008: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x0009: 'TLS_RSA_WITH_DES_CBC_SHA',
    0x000A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    0x000B: 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
    0x000C: 'TLS_DH_DSS_WITH_DES_CBC_SHA',
    0x000D: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
    0x000E: 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x000F: 'TLS_DH_RSA_WITH_DES_CBC_SHA',
    0x0010: 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
    0x0011: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
    0x0012: 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
    0x0013: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
    0x0014: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x0015: 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
    0x0016: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    0x0017: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
    0x0018: 'TLS_DH_anon_WITH_RC4_128_MD5',
    0x0019: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
    0x001A: 'TLS_DH_anon_WITH_DES_CBC_SHA',
    0x001B: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
    0x001E: 'TLS_KRB5_WITH_DES_CBC_SHA',
    0x001F: 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
    0x0020: 'TLS_KRB5_WITH_RC4_128_SHA',
    0x0021: 'TLS_KRB5_WITH_IDEA_CBC_SHA',
    0x0022: 'TLS_KRB5_WITH_DES_CBC_MD5',
    0x0023: 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
    0x0024: 'TLS_KRB5_WITH_RC4_128_MD5',
    0x0025: 'TLS_KRB5_WITH_IDEA_CBC_MD5',
    0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    0x0030: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
    0x0031: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
    0x0032: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
    0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    0x0034: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
    0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    0x0036: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
    0x0037: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
    0x0038: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
    0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    0x003A: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
    0x003B: 'TLS_RSA_WITH_NULL_SHA256',
    0x003C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    0x003D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    0x003E: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
    0x003F: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
    0x0040: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
    0x0067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    0x0068: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
    0x0069: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
    0x006A: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
    0x006B: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    0x006C: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
    0x006D: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
} #https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
# openssl ciphers -v
# import ssl
# print(ssl._RESTRICTED_SERVER_CIPHERS)
#WEAK_CIPHERS = [0x0005, 0x0004, 0x0003, 0x0002, 0x0001] # 4164121, 9771146 Copied these from somewhere, but removed after analysis was done.
# SHOULD MORE BE INCLUDED???
# THESE CORRESPOND TO THE FOLLOWING CIPHERS: This section does not represent these digits accurately.
# 0x00,0x01		TLS_RSA_WITH_NULL_MD5	TLS_RSA_NULL_MD5	TLS_RSA_WITH_NULL_MD5
# 0x00,0x02		TLS_RSA_WITH_NULL_SHA	TLS_RSA_NULL_SHA1	TLS_RSA_WITH_NULL_SHA
# 0x00,0x03		TLS_RSA_EXPORT_WITH_RC4_40_MD5		TLS_RSA_EXPORT_WITH_RC4_40_MD5
# 0x00,0x04		TLS_RSA_WITH_RC4_128_MD5	TLS_RSA_ARCFOUR_128_MD5	TLS_RSA_WITH_RC4_128_MD5
# 0x00,0x05		TLS_RSA_WITH_RC4_128_SHA

#0xC0,0x34




# Source for below function: # SOURCE: https://www.stationx.net/common-ports-cheat-sheet/
def is_likely_encrypted(packet):
    """
    Determine if a given network packet is likely to contain encrypted data.

    This function uses multiple heuristics to assess the likelihood of encryption:
    1. Checks if the packet is using ports commonly associated with encrypted protocols.
    2. Looks for the presence of TLS/SSL layers.
    3. Searches for specific strings that might indicate encryption.

    Args:
        packet (scapy.packet.Packet): A Scapy packet object to analyze.

    Returns:
        bool: True if the packet is likely encrypted, False otherwise.

    Note:
        This function provides an estimate and may not be 100% accurate in all cases.
        It's based on common indicators of encryption rather than deep packet inspection.
    """
    # Set of ports commonly used for encrypted traffic
    # These ports are associated with secure versions of common protocols
    encrypted_ports = {
        443,   # HTTPS (HTTP Secure)
        465,   # SMTPS (Simple Mail Transfer Protocol Secure)
        993,   # IMAPS (Internet Message Access Protocol Secure)
        995,   # POP3S (Post Office Protocol 3 Secure)
        8443   # HTTPS (alternative port)
    }
    # Source: https://www.stationx.net/common-ports-cheat-sheet/

    # Check if the packet uses TCP protocol
    if packet.haslayer(TCP):
        # Check if either the source or destination port is in our list of encrypted ports
        if packet[TCP].dport in encrypted_ports or packet[TCP].sport in encrypted_ports:
            return True

    # Check if the packet uses UDP protocol
    # Some encrypted protocols like DTLS use UDP
    elif packet.haslayer(UDP):
        # Check if either the source or destination port is in our list of encrypted ports
        if packet[UDP].dport in encrypted_ports or packet[UDP].sport in encrypted_ports:
            return True

    # Check for the presence of TLS/SSL layer
    # This is a strong indicator of encryption
    if packet.haslayer(TLS):
        return True

    # Check for specific strings that might indicate TLS/SSL
    # These strings might be present in packets during the TLS handshake
    if 'TLS_detected' in packet or 'Possible_TLS' in packet:
        return True

    # If none of the above conditions are met, the packet is likely not encrypted
    return False

def safe_get_ciphers(packet):
    """
    Safely extract cipher suites from a TLS ClientHello message in a network packet.

    This function attempts to retrieve the list of cipher suites offered by a client
    during the TLS handshake process. It's designed to handle potential errors
    gracefully, returning an empty list if the cipher suites can't be extracted.

    Args:
        packet (scapy.packet.Packet): A Scapy packet object to analyze.

    Returns:
        list: A list of cipher suites if found in a TLS ClientHello message,
              or an empty list if not found or in case of any error.

    Note:
        This function assumes the use of the Scapy library with TLS layer support.
        It only processes TLS ClientHello messages, which are sent by clients
        at the beginning of a TLS handshake to suggest cipher suites to the server.
    """
    try:
        # Check if the packet has a TLS layer
        if packet.haslayer(TLS):
            # Get the TLS layer from the packet
            tls_layer = packet[TLS]

            # Check if the TLS layer has a 'msg' attribute and if it's not empty
            if hasattr(tls_layer, 'msg') and tls_layer.msg:
                # Iterate through all messages in the TLS layer
                for msg in tls_layer.msg:
                    # Check if the message is a TLS ClientHello
                    if isinstance(msg, TLSClientHello):
                        # If it is, return the cipher suites offered by the client
                        return msg.cipher_suites

    except AttributeError:
        # If any AttributeError occurs during the process, we catch it here
        # This could happen if the packet structure is unexpected
        pass

    # If no cipher suites are found or any error occurs, return an empty list
    return []



def process_packet(packet, protocols, ip_sources, ip_destinations, tcp_ports, udp_ports, tcp_flags,
                   packet_sizes, arp_operations, icmp_types, http_methods, data, timestamp):
    if Ether in packet:
        protocols['Ethernet'] += 1

    if IP in packet:
        protocols['IP'] += 1
        ip_sources[packet[IP].src] += 1
        ip_destinations[packet[IP].dst] += 1
        packet_sizes.append(len(packet))

        if TCP in packet:
            process_tcp_packet(packet, protocols, tcp_ports, tcp_flags, data, timestamp, len(packet), http_methods)
        elif UDP in packet:
            process_udp_packet(packet, protocols, udp_ports, data, timestamp, len(packet))
        elif ICMP in packet:
            process_icmp_packet(packet, protocols, icmp_types, data, timestamp, len(packet))
    elif ARP in packet:
        process_arp_packet(packet, protocols, arp_operations, data, timestamp, len(packet))

def process_tcp_packet(packet, protocols, tcp_ports, tcp_flags, data, timestamp, packet_len, http_methods):
    protocols['TCP'] += 1
    tcp_ports[packet[TCP].sport] += 1
    tcp_ports[packet[TCP].dport] += 1
    tcp_flags[packet[TCP].flags] += 1

    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
        payload = str(packet[TCP].payload)
        for method in ['GET', 'POST', 'PUT', 'DELETE']:
            if method in payload:
                http_methods[method] += 1
                break

    data[timestamp]['timestamp'] = timestamp
    data[timestamp]['TCP_packets'] += 1
    data[timestamp]['TCP_bytes'] += packet_len
    data[timestamp]['TCP_flags'] = packet[TCP].flags

def process_udp_packet(packet, protocols, udp_ports, data, timestamp, packet_len):
    protocols['UDP'] += 1
    udp_ports[packet[UDP].sport] += 1
    udp_ports[packet[UDP].dport] += 1
    data[timestamp]['UDP_packets'] += 1
    data[timestamp]['UDP_bytes'] += packet_len

def process_icmp_packet(packet, protocols, icmp_types, data, timestamp, packet_len):
    protocols['ICMP'] += 1
    icmp_types[packet[ICMP].type] += 1
    data[timestamp]['timestamp'] = timestamp
    data[timestamp]['ICMP_packets'] += 1
    data[timestamp]['ICMP_bytes'] += packet_len

def process_arp_packet(packet, protocols, arp_operations, data, timestamp, packet_len):
    protocols['ARP'] += 1
    arp_operations[packet[ARP].op] += 1
    data[timestamp]['timestamp'] = timestamp
    data[timestamp]['ARP_packets'] += 1
    data[timestamp]['ARP_bytes'] += packet_len

def process_encryption(packet, data, timestamp, non_encrypted_packets, sslv2_packets, weak_cipher_packets, unknown_cipher_packets):
    if TLS in packet:
        data[timestamp]['TLS_detected'] = True
        ciphers = safe_get_ciphers(packet)
        weak_ciphers = [c for c in ciphers if any(weak in str(c) for weak in WEAK_CIPHERS)]
        unknown_ciphers = [c for c in ciphers if c not in TLS_CIPHER_SUITES]

        if weak_ciphers:
            weak_cipher_packets.append(packet)
        if unknown_ciphers:
            unknown_cipher_packets.append(packet)

    if SSLv2 in packet:
        sslv2_packets.append(packet)

    if not is_likely_encrypted(packet):
        non_encrypted_packets.append(packet)

def detect_quic_packets(file_path):
    quic_count = 0
    try:
        capture = pyshark.FileCapture(file_path, display_filter='quic')
        for _ in capture:
            quic_count += 1
    except Exception as e:
        print(f"Error in pyshark QUIC detection: {e}")
    finally:
        capture.close()
    return quic_count

def process_pcapng(file_path):
    start_time = time.time()
    print(f"Starting analysis of {file_path}...")

    packets = rdpcap(file_path)
    total_packets = len(packets)
    print(f"Total packets: {total_packets}")

    protocols = Counter()
    ip_sources = Counter()
    ip_destinations = Counter()
    tcp_ports = Counter()
    udp_ports = Counter()
    tcp_flags = Counter()
    packet_sizes = []
    arp_operations = Counter()
    icmp_types = Counter()
    http_methods = Counter()
    data = defaultdict(lambda: defaultdict(int))
    non_encrypted_packets = []
    sslv2_packets = []
    weak_cipher_packets = []
    unknown_cipher_packets = []

    quic_count = detect_quic_packets(file_path)
    protocols['QUIC'] = quic_count

    print("Processing packets...")
    for packet in tqdm(packets, total=total_packets, desc="Processing"):
        timestamp = datetime.fromtimestamp(float(packet.time))
        process_packet(packet, protocols, ip_sources, ip_destinations, tcp_ports, udp_ports, tcp_flags,
                       packet_sizes, arp_operations, icmp_types, http_methods, data, timestamp)
        process_encryption(packet, data, timestamp, non_encrypted_packets, sslv2_packets, weak_cipher_packets, unknown_cipher_packets)

    df = pd.DataFrame(data.values()).sort_values('timestamp')

    total_transport_packets = sum(protocols[p] for p in ['TCP', 'UDP', 'QUIC'])
    quic_percentage = (protocols['QUIC'] / total_transport_packets) * 100 if total_transport_packets > 0 else 0

    summary = {
        "total_packets": total_packets,
        "unique_ip_sources": len(ip_sources),
        "unique_ip_destinations": len(ip_destinations),
        "protocols": protocols,
        "top_tcp_ports": tcp_ports.most_common(10),
        "top_udp_ports": udp_ports.most_common(10),
        "tcp_flags": tcp_flags,
        "top_ip_sources": ip_sources.most_common(10),
        "top_ip_destinations": ip_destinations.most_common(10),
        "packet_size_stats": {
            "min": min(packet_sizes),
            "max": max(packet_sizes),
            "mean": statistics.mean(packet_sizes),
            "median": statistics.median(packet_sizes)
        },
        "arp_operations": arp_operations,
        "icmp_types": icmp_types,
        "http_methods": http_methods,
        "quic_packets": quic_count,
        "quic_percentage": quic_percentage,
        "non_encrypted_packets": len(non_encrypted_packets),
        "sslv2_packets": len(sslv2_packets),
        "weak_cipher_packets": len(weak_cipher_packets),
        "unknown_cipher_packets": len(unknown_cipher_packets)
    }

    end_time = time.time()
    summary["analysis_time"] = end_time - start_time

    return summary, df, packets, non_encrypted_packets, sslv2_packets, weak_cipher_packets, unknown_cipher_packets

def analyze_security_issues(packets, sslv2_packets, weak_cipher_packets, unknown_cipher_packets):
    """
    Analyze network packets for potential security issues, focusing on FTP authentication.

    This function examines the provided packets for several security concerns:
    1. Use of deprecated and insecure SSLv2 protocol
    2. Use of weak TLS ciphers
    3. Use of unknown TLS ciphers
    4. FTP authentication in cleartext

    Args:
        packets (list): List of all captured network packets
        sslv2_packets (list): List of packets using SSLv2 protocol
        weak_cipher_packets (list): List of packets using weak TLS ciphers
        unknown_cipher_packets (list): List of packets using unknown TLS ciphers

    Returns:
        list: A list of strings describing detected security issues

    Note:
        This function specifically looks for FTP authentication packets, which are known
        to transmit credentials in cleartext. I added this after Orion told me to search for FTP in Wireshark.
    """
    security_issues = []

    if sslv2_packets:
        security_issues.append(
            f"WARNING: {len(sslv2_packets)} packets using insecure SSLv2 detected!"
        )

    if weak_cipher_packets:
        security_issues.append(
            f"WARNING: {len(weak_cipher_packets)} packets using weak TLS ciphers detected!"
        )

    if unknown_cipher_packets:
        security_issues.append(
            f"WARNING: {len(unknown_cipher_packets)} packets using unknown TLS ciphers detected!"
        )

    # FTP authentication detection
    ftp_auth_regex = re.compile(r'USER|PASS', re.IGNORECASE)
    ftp_auth_packets = []

    for packet in packets:
        if TCP in packet and Raw in packet:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if packet[TCP].dport == 21 or packet[TCP].sport == 21:  # FTP control port
                if ftp_auth_regex.search(payload):
                    ftp_auth_packets.append(packet)

    if ftp_auth_packets:
        security_issues.append(f"WARNING: {len(ftp_auth_packets)} FTP authentication packets detected in cleartext!")
        for packet in ftp_auth_packets[:5]:  # Report details for up to 5 packets
            security_issues.append(
                f"FTP auth packet detected at {packet.time}. "
                f"Src IP: {packet[IP].src}, Dst IP: {packet[IP].dst}, "
                f"Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}"
            )
        if len(ftp_auth_packets) > 5:
            security_issues.append(f"... and {len(ftp_auth_packets) - 5} more FTP auth packets.")

    # Calculate percentages for a more detailed risk assessment
    total_analyzed_packets = len(sslv2_packets) + len(weak_cipher_packets) + len(unknown_cipher_packets)
    if total_analyzed_packets > 0:
        sslv2_percentage = (len(sslv2_packets) / total_analyzed_packets) * 100
        weak_cipher_percentage = (len(weak_cipher_packets) / total_analyzed_packets) * 100
        unknown_cipher_percentage = (len(unknown_cipher_packets) / total_analyzed_packets) * 100

        security_issues.append(f"SUMMARY: Of the analyzed packets:")
        security_issues.append(f"  - {sslv2_percentage:.2f}% use SSLv2")
        security_issues.append(f"  - {weak_cipher_percentage:.2f}% use weak ciphers")
        security_issues.append(f"  - {unknown_cipher_percentage:.2f}% use unknown ciphers")
        security_issues.append(f"  - {len(ftp_auth_packets)} FTP authentication packets detected")

    return security_issues


def print_analysis(df, packets, security_issues):
    print("\n--- Network Traffic Analysis ---")
    print(f"Total packets: {len(packets)}")
    print(f"Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")

    print("\nProtocol distribution:")
    for col in df.columns:
        if col.endswith('_packets'):
            protocol = col.split('_')[0]
            packets = df[f'{protocol}_packets'].sum()
            bytes = df[f'{protocol}_bytes'].sum()
            print(f"- {protocol}: {packets} packets, {bytes} bytes")

    if 'TCP_flags' in df.columns:
        print("\nTCP Flags distribution:")
        flags = df['TCP_flags'].value_counts()
        for flag, count in flags.items():
            print(f"- {flag}: {count} packets")

    print("\nSecurity Issues:")
    for issue in security_issues:
        print(issue)


def analyze_sslv2_packets(sslv2_packets, summary):
    """
    Analyze packets using the deprecated SSLv2 protocol.

    This function examines SSLv2 packets, extracting key information such as
    source and destination IP addresses, ports, timestamps, and packet lengths.
    It then provides a summary of the findings, including details of each SSLv2
    packet and lists of unique sources and destinations. It now also incorporates
    relevant information from the overall traffic summary.

    Args:
        sslv2_packets (list): List of Scapy packet objects identified as using SSLv2
        summary (dict): Summary dictionary containing overall network traffic statistics

    Returns:
        list: A list of dictionaries, each containing details of an SSLv2 packet

    Note:
        SSLv2 is a deprecated and insecure protocol. Its presence in network
        traffic is a significant security concern that should be addressed.
    """
    # Initialize a list to store details of each SSLv2 packet
    sslv2_details = []

    # Iterate through each SSLv2 packet
    for packet in sslv2_packets:
        # Check if the packet has an IP layer
        if IP in packet:
            # Extract basic information from the packet
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = datetime.fromtimestamp(float(packet.time))

            # Create a dictionary to store packet details
            details = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'length': len(packet)
            }

            # If the packet has a TCP layer, extract port information
            if TCP in packet:
                details['src_port'] = packet[TCP].sport
                details['dst_port'] = packet[TCP].dport

            # Add the packet details to our list
            sslv2_details.append(details)

    # If SSLv2 packets were found, print detailed information
    if sslv2_details:
        print("\nSSLv2 Packet Details:")
        for detail in sslv2_details:
            print(f"Time: {detail['timestamp']}, "
                  f"Source: {detail['src_ip']}:{detail.get('src_port', 'N/A')}, "
                  f"Destination: {detail['dst_ip']}:{detail.get('dst_port', 'N/A')}, "
                  f"Length: {detail['length']} bytes")

        # Collect and display unique source and destination IP addresses
        unique_sources = set(detail['src_ip'] for detail in sslv2_details)
        unique_destinations = set(detail['dst_ip'] for detail in sslv2_details)

        print(f"\nUnique SSLv2 Sources: {', '.join(unique_sources)}")
        print(f"Unique SSLv2 Destinations: {', '.join(unique_destinations)}")

        # Additional analysis using summary information
        total_packets = summary['total_packets']
        sslv2_count = len(sslv2_packets)
        sslv2_percentage = (sslv2_count / total_packets) * 100

        print(f"\nSSLv2 Statistics:")
        print(f"Total SSLv2 packets: {sslv2_count}")
        print(f"Percentage of total traffic: {sslv2_percentage:.2f}%")

        # Analyze SSLv2 packet sizes
        sslv2_sizes = [len(packet) for packet in sslv2_packets]
        avg_size = sum(sslv2_sizes) / len(sslv2_sizes)
        min_size = min(sslv2_sizes)
        max_size = max(sslv2_sizes)

        print(f"Average SSLv2 packet size: {avg_size:.2f} bytes")
        print(f"Minimum SSLv2 packet size: {min_size} bytes")
        print(f"Maximum SSLv2 packet size: {max_size} bytes")

        # Analyze SSLv2 traffic over time
        time_distribution = Counter([detail['timestamp'].strftime('%Y-%m-%d %H:%M') for detail in sslv2_details])
        peak_time = max(time_distribution, key=time_distribution.get)
        print(f"Peak SSLv2 traffic time: {peak_time} with {time_distribution[peak_time]} packets")

        # Compare with overall traffic patterns
        if 'TCP_packets' in summary:
            tcp_percentage = (summary['TCP_packets'] / total_packets) * 100
            print(f"\nComparison with overall TCP traffic:")
            print(f"SSLv2 percentage: {sslv2_percentage:.2f}%")
            print(f"Overall TCP percentage: {tcp_percentage:.2f}%")

    else:
        print("\nNo SSLv2 packets found.")

    return sslv2_details





def write_full_analysis(summary, df, security_issues, sslv2_details): #removed packets
    with open('../data/full_analysis.txt', 'w') as f:
        f.write("Network Traffic Analysis Report\n")
        f.write("===============================\n\n")

        # Basic Statistics
        f.write("1. Basic Statistics\n")
        f.write("-------------------\n")
        f.write(f"Total packets analyzed: {summary['total_packets']}\n")
        f.write(f"Time range: {df['timestamp'].min()} to {df['timestamp'].max()}\n")
        f.write(f"Duration: {(df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600:.2f} hours\n")
        f.write(f"Unique IP sources: {summary['unique_ip_sources']}\n")
        f.write(f"Unique IP destinations: {summary['unique_ip_destinations']}\n")
        f.write(f"Average packet size: {summary['packet_size_stats']['mean']:.2f} bytes\n")
        f.write(f"Median packet size: {summary['packet_size_stats']['median']:.2f} bytes\n")
        f.write(f"Minimum packet size: {summary['packet_size_stats']['min']} bytes\n")
        f.write(f"Maximum packet size: {summary['packet_size_stats']['max']} bytes\n\n")

        # Protocol Distribution
        f.write("2. Protocol Distribution\n")
        f.write("------------------------\n")
        for protocol, count in summary['protocols'].items():
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- {protocol}: {count} packets ({percentage:.2f}%)\n")
        f.write("\n")

        # QUIC Analysis
        f.write("3. QUIC Analysis\n")
        f.write("-----------------\n")
        f.write(f"QUIC packets: {summary['quic_packets']}\n")
        f.write(f"QUIC percentage: {summary['quic_percentage']:.2f}%\n\n")

        # TCP Analysis
        f.write("4. TCP Analysis\n")
        f.write("-----------------\n")
        f.write("TCP Flags distribution:\n")
        for flag, count in summary['tcp_flags'].items():
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- {flag}: {count} packets ({percentage:.2f}%)\n")
        f.write("\n")

        # Security Analysis
        f.write("5. Security Analysis\n")
        f.write("---------------------\n")
        f.write("a) General Security Issues:\n")
        for issue in security_issues:
            f.write(f"- {issue}\n")

        f.write("\nb) SSLv2 Usage (Deprecated and Insecure):\n")
        f.write(f"Total SSLv2 packets: {summary['sslv2_packets']}\n")
        if sslv2_details:
            f.write(f"Unique SSLv2 Sources: {', '.join(set(detail['src_ip'] for detail in sslv2_details))}\n")
            f.write(f"Unique SSLv2 Destinations: {', '.join(set(detail['dst_ip'] for detail in sslv2_details))}\n")

        f.write("\nc) Non-encrypted Traffic:\n")
        f.write(f"Total non-encrypted packets: {summary['non_encrypted_packets']} "
                f"({(summary['non_encrypted_packets'] / summary['total_packets']) * 100:.2f}% of total)\n")

        f.write("\nd) Weak Cipher Usage:\n")
        f.write(f"Packets using weak ciphers: {summary['weak_cipher_packets']} "
                f"({(summary['weak_cipher_packets'] / summary['total_packets']) * 100:.2f}% of total)\n")

        f.write("\ne) Unknown Cipher Usage:\n")
        f.write(f"Packets using unknown ciphers: {summary['unknown_cipher_packets']} "
                f"({(summary['unknown_cipher_packets'] / summary['total_packets']) * 100:.2f}% of total)\n\n")

        # Traffic Patterns
        f.write("6. Traffic Patterns\n")
        f.write("-------------------\n")
        hourly_traffic = df.set_index('timestamp').resample('H').sum()
        peak_hour = hourly_traffic.filter(regex='_packets').sum(axis=1).idxmax()
        f.write(f"Peak traffic hour: {peak_hour}\n")
        f.write(f"Packets in peak hour: {hourly_traffic.loc[peak_hour].filter(regex='_packets').sum()}\n")
        f.write(f"Bytes in peak hour: {hourly_traffic.loc[peak_hour].filter(regex='_bytes').sum()}\n\n")

        # IP Analysis
        f.write("7. IP Analysis\n")
        f.write("---------------\n")
        f.write("Top 10 source IPs:\n")
        for ip, count in summary['top_ip_sources']:
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- {ip}: {count} packets ({percentage:.2f}%)\n")
        f.write("\nTop 10 destination IPs:\n")
        for ip, count in summary['top_ip_destinations']:
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- {ip}: {count} packets ({percentage:.2f}%)\n")
        f.write("\n")

        # Port Analysis
        f.write("8. Port Analysis\n")
        f.write("-----------------\n")
        f.write("Top 10 TCP ports:\n")
        for port, count in summary['top_tcp_ports']:
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- {port}: {count} packets ({percentage:.2f}%)\n")
        f.write("\nTop 10 UDP ports:\n")
        for port, count in summary['top_udp_ports']:
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- {port}: {count} packets ({percentage:.2f}%)\n")
        f.write("\n")

        # ARP Analysis
        f.write("9. ARP Analysis\n")
        f.write("-----------------\n")
        for op, count in summary['arp_operations'].items():
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- Operation {op}: {count} packets ({percentage:.2f}%)\n")
        f.write("\n")

        # ICMP Analysis
        f.write("10. ICMP Analysis\n")
        f.write("------------------\n")
        for icmp_type, count in summary['icmp_types'].items():
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- Type {icmp_type}: {count} packets ({percentage:.2f}%)\n")
        f.write("\n")

        # HTTP Methods
        f.write("11. HTTP Methods\n")
        f.write("------------------\n")
        for method, count in summary['http_methods'].items():
            percentage = (count / summary['total_packets']) * 100
            f.write(f"- {method}: {count} packets ({percentage:.2f}%)\n")
        f.write("\n")

        # Additional Insights
        f.write("12. Additional Insights\n")
        f.write("-----------------------\n")
        duration_seconds = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        f.write(f"Average packets per second: {summary['total_packets'] / duration_seconds:.2f}\n")
        total_bytes = df.filter(regex='_bytes').sum().sum()
        f.write(f"Average bytes per second: {total_bytes / duration_seconds:.2f}\n")
        f.write(f"Analysis completed in: {summary['analysis_time']:.2f} seconds\n")

    print("Full analysis written to '../data/full_analysis.txt'")



def prepare_data_for_isolation_forest(df, summary):
    """
    Prepare network traffic data for anomaly detection using Isolation Forest.

    This function processes a DataFrame of network traffic data, aggregating it by minute
    and creating features that can be used to detect anomalies. It handles missing data,
    creates ratios and rates, and normalizes the features. It now also incorporates
    relevant features from the summary.

    Args:
        df (pd.DataFrame): Input DataFrame containing network traffic data.
                           Expected to have a 'timestamp' column and various packet/byte columns.
        summary (dict): Summary dictionary containing additional network traffic statistics.

    Returns:
        pd.DataFrame: Normalized features ready for use in Isolation Forest algorithm.
    """
    print("Preparing data for isolation forest...")

    # Round timestamps to the nearest minute for aggregation
    df['minute'] = df['timestamp'].dt.floor('T')

    # Dynamically determine packet and byte columns
    packet_columns = [col for col in df.columns if col.endswith('_packets')]
    byte_columns = [col for col in df.columns if col.endswith('_bytes')]

    # Create aggregation dictionary
    agg_dict = {**{col: 'sum' for col in packet_columns},
                **{col: 'sum' for col in byte_columns}}

    # Aggregate data by minute
    agg_df = df.groupby('minute').agg(agg_dict).reset_index()

    # Initialize features DataFrame
    features_df = pd.DataFrame()

    # Add absolute values
    features_df['total_packets'] = agg_df[packet_columns].sum(axis=1)
    features_df['total_bytes'] = agg_df[byte_columns].sum(axis=1)

    # Calculate encrypted traffic ratio
    if 'TLS_packets' in agg_df.columns and 'TCP_packets' in agg_df.columns:
        features_df['encrypted_ratio'] = agg_df['TLS_packets'] / agg_df['TCP_packets'].replace(0, 1)

    # Calculate average bytes per packet
    features_df['bytes_per_packet'] = features_df['total_bytes'] / features_df['total_packets'].replace(0, 1)

    # Calculate protocol ratios
    for protocol in set([col.split('_')[0] for col in packet_columns]):
        if f'{protocol}_packets' in agg_df.columns:
            features_df[f'{protocol}_ratio'] = agg_df[f'{protocol}_packets'] / features_df['total_packets'].replace(0, 1)

    # Add time-based features
    features_df['hour'] = agg_df['minute'].dt.hour
    features_df['day_of_week'] = agg_df['minute'].dt.dayofweek

    # Add new features from summary
    total_packets = summary['total_packets']
    features_df['quic_ratio'] = summary['quic_percentage'] / 100  # Convert percentage to ratio
    features_df['non_encrypted_ratio'] = summary['non_encrypted_packets'] / total_packets
    features_df['sslv2_ratio'] = summary['sslv2_packets'] / total_packets
    features_df['weak_cipher_ratio'] = summary['weak_cipher_packets'] / total_packets
    features_df['unknown_cipher_ratio'] = summary['unknown_cipher_packets'] / total_packets

    # Add packet size statistics
    features_df['packet_size_mean'] = summary['packet_size_stats']['mean']
    features_df['packet_size_median'] = summary['packet_size_stats']['median']
    features_df['packet_size_min'] = summary['packet_size_stats']['min']
    features_df['packet_size_max'] = summary['packet_size_stats']['max']

    # Add top protocol ratios
    for protocol, count in summary['protocols'].items():
        features_df[f'{protocol.lower()}_ratio'] = count / total_packets

    # Handle infinite values and NaNs
    features_df = features_df.replace([np.inf, -np.inf], np.nan)

    # For columns that are all NaN, replace with 0
    for col in features_df.columns:
        if features_df[col].isna().all():
            features_df[col] = 0

    # For remaining NaNs, use forward fill, then backward fill, then 0
    features_df = features_df.fillna(method='ffill').fillna(method='bfill').fillna(0)

    # Normalize features
    scaler = StandardScaler()
    features_normalized = scaler.fit_transform(features_df)

    return pd.DataFrame(features_normalized, columns=features_df.columns)


def write_non_encrypted_to_csv(non_encrypted_packets, output_file):
    """
    Write non-encrypted packet data to a CSV file.
    """
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL, escapechar='\\')
        writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Raw Content'])

        for packet in non_encrypted_packets:
            timestamp = datetime.fromtimestamp(float(packet.time))
            src_ip = packet[IP].src if packet.haslayer(IP) else 'N/A'
            dst_ip = packet[IP].dst if packet.haslayer(IP) else 'N/A'
            protocol = packet.lastlayer().name
            length = len(packet)
            raw_content = packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else 'N/A'

            writer.writerow([timestamp, src_ip, dst_ip, protocol, length, raw_content])


def write_summary_to_csv(summary, file_path):
    """
    Write the summary dictionary to a CSV file.

    Args:
    summary (dict): The summary dictionary to write
    file_path (str): The path to the output CSV file
    """
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for key, value in summary.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    writer.writerow([f"{key}_{sub_key}", sub_value])
            elif isinstance(value, list):
                writer.writerow([key, ', '.join(map(str, value))])
            else:
                writer.writerow([key, value])



def main():
    """
    Main function to orchestrate the network packet analysis process.

    This function performs the following steps:
    1. Process the PCAPNG file
    2. Analyze security issues
    3. Print initial analysis
    4. Analyze SSLv2 packets in detail
    5. Write full analysis to a file
    6. Prepare data for Isolation Forest anomaly detection
    7. Write processed data to CSV files

    All output files are saved in the '../data' directory.
    """
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    output_dir = os.path.join('..', 'data')
    os.makedirs(output_dir, exist_ok=True)

    # File path for the PCAPNG file to be analyzed
    #file_path = os.path.join('..', 'ghosts_test_run0.pcapng')
    file_path = os.path.join('..', 'one_million_packets.pcapng')

    logging.info("Starting packet processing...")
    try:
        summary, df, packets, non_encrypted_packets, sslv2_packets, weak_cipher_packets, unknown_cipher_packets = process_pcapng(file_path)
    except Exception as e:
        logging.error(f"Error processing PCAPNG file: {e}")
        return

    logging.info("Writing non-encrypted packets to CSV...")
    try:
        write_non_encrypted_to_csv(non_encrypted_packets, os.path.join(output_dir, 'Probable_non_encrypted_data.csv'))
    except Exception as e:
        logging.error(f"Error writing non-encrypted packets to CSV: {e}")

    logging.info("Analyzing security issues...")
    security_issues = analyze_security_issues(packets, sslv2_packets, weak_cipher_packets, unknown_cipher_packets)

    logging.info("Analyzing SSLv2 packets...")
    sslv2_details = analyze_sslv2_packets(sslv2_packets, summary)

    logging.info("Writing full analysis...")
    try:
        write_full_analysis(summary, df, security_issues, sslv2_details) #, output_file=os.path.join(output_dir, 'full_analysis.txt')
        logging.info(f"Full analysis written to {os.path.join(output_dir, 'full_analysis.txt')}")
    except Exception as e:
        logging.error(f"Error writing full analysis: {e}")

    logging.info("Preparing data for isolation forest...")
    try:
        isolation_forest_data = prepare_data_for_isolation_forest(df, summary)
        isolation_forest_data.to_csv(os.path.join(output_dir, 'isolation_forest_data.csv'), index=False)
        logging.info(f"Data for isolation forest analysis written to {os.path.join(output_dir, 'isolation_forest_data.csv')}")
    except Exception as e:
        logging.error(f"Error preparing data for isolation forest: {e}")
        logging.info("Skipping isolation forest data preparation.")

    logging.info("Writing all packet data...")
    try:
        df.to_csv(os.path.join(output_dir, 'all_packet_data.csv'), index=False)
        logging.info(f"All packet data written to {os.path.join(output_dir, 'all_packet_data.csv')}")
    except Exception as e:
        logging.error(f"Error writing all packet data: {e}")

    logging.info("Writing summary data...")
    try:
        write_summary_to_csv(summary, os.path.join(output_dir, 'summary_data.csv'))
        logging.info(f"Summary data written to {os.path.join(output_dir, 'summary_data.csv')}")
    except Exception as e:
        logging.error(f"Error writing summary data: {e}")

    if sslv2_details:
        logging.info("Writing SSLv2 details...")
        try:
            pd.DataFrame(sslv2_details).to_csv(os.path.join(output_dir, 'sslv2_details.csv'), index=False)
            logging.info(f"SSLv2 packet details written to {os.path.join(output_dir, 'sslv2_details.csv')}")
        except Exception as e:
            logging.error(f"Error writing SSLv2 details: {e}")
    else:
        logging.info("No SSLv2 packets found, skipping sslv2_details.csv creation")

    logging.info("Processing complete!")

if __name__ == "__main__":
    main()