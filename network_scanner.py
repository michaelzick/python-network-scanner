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

    print('IP\t\tMAC Address\n----------------------------------')
    for answer in answered_list:
        print(answer[1].psrc + '\t' + answer[1].hwsrc)


print_answered_list('10.0.2.1/24')
