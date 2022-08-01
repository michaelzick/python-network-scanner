#!/usr/bin/env python3

from numpy import broadcast
import scapy.all as scapy


def get_arp_request(ip):
    return scapy.ARP(pdst=ip)


def get_broadcast():
    return scapy.Ether(dst='ff:ff:ff:ff:ff:ff')


def get_answered_list(ip):
    arp_request = get_arp_request(ip)
    broadcast = get_broadcast()
    arp_request_broadcast = broadcast/arp_request
    return scapy.srp(arp_request_broadcast,
                     timeout=1, verbose=False)[0]


def print_answered_list(ip):
    answered_list = get_answered_list(ip)
    clients_list = []

    print('IP\t\tMAC Address\n----------------------------------')
    for answer in answered_list:
        client_dict = {'ip': answer[1].psrc, 'mac': answer[1].hwsrc}
        clients_list.append(client_dict)

    print(clients_list)


print_answered_list('10.0.2.1/24')
