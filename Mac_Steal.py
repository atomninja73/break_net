#!/usr/bin/env python

import subprocess
import scapy.all as scapy
import re
import time


def get_self_ip():
    output = subprocess.check_output(["ifconfig", "eth0"])
    output = str(output)
    ip_addr = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", output)
    # ip_addr[0] = IP,  ip_addr[1] = mask ip_addr[2] = broadcast
    return ip_addr


def get_self_mac():
    output = subprocess.check_output(["ifconfig", "eth0"])
    output = str(output)
    mac_addr = re.findall("[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}", output)
    return mac_addr[0]


def get_default_mac():
    output = subprocess.check_output(["arp", "-a"])
    output = str(output)
    default_mac = re.findall("[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}", output)
    print("-----------------------------------------------------\n")
    print("MAC address of the router : ", default_mac[0], "\n")
    print("-----------------------------------------------------\n")

    return default_mac[0]


def get_network_range():
    self_ip = get_self_ip()
    ip = self_ip[0]
    mask = self_ip[1]
    ip = str(ip)
    mask = str(mask)
    if mask == "255.255.128.0":
        scan_range = (ip + "/17")
    elif mask == "255.255.192.0":
        scan_range = (ip + "/18")
    elif mask == "255.255.224.0":
        scan_range = (ip + "/19")
    elif mask == "255.255.240.0":
        scan_range = (ip + "/20")
    elif mask == "255.255.248.0":
        scan_range = (ip + "/21")
    elif mask == "255.255.252.0":
        scan_range = (ip + "/22")
    elif mask == "255.255.254.0":
        scan_range = (ip + "/23")
    elif mask == "255.255.255.0":
        scan_range = (ip + "/24")
    elif mask == "255.255.255.128":
        scan_range = (ip + "/25")
    elif mask == "255.255.255.192":
        scan_range = (ip + "/26")
    elif mask == "255.255.255.224":
        scan_range = (ip + "/27")
    elif mask == "255.255.255.240":
        scan_range = (ip + "/28")
    elif mask == "255.255.255.248":
        scan_range = (ip + "/29")
    elif mask == "255.255.255.252":
        scan_range = (ip + "/30")
    else:
        scan_range = 0
        print("Error in the subnet mask")
    return scan_range


def scan_range():
    ip = get_network_range()
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result():
    while True:
        results_list = scan_range()
        print("--------------------------------------------")
        print("IP\t\t\tMAC Address")
        print("--------------------------------------------")
        for client in results_list:
            print(client["ip"] + "\t\t" + client["mac"])
        print("--------------------------------------------")
        time.sleep(60)


get_default_mac()
print_result()
