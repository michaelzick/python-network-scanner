#!/usr/bin/env python3

from numpy import broadcast
import scapy.all as scapy


def get_arp_request(ip):
    return scapy.ARP(pdst=ip)


def get_broadcast():
    return scapy.Ether(dst='ff:ff:ff:ff:ff:ff')


def get_clients_list(ip):
    clients_list = []
    arp_request = get_arp_request(ip)
    broadcast = get_broadcast()
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]

    for answer in answered_list:
        client_dict = {'ip': answer[1].psrc, 'mac': answer[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_clients_list(ip):
    clients_list = get_clients_list(ip)

    print('IP\t\tMAC Address\n----------------------------------')

    for client in clients_list:
        print(client['ip'] + '\t' + client['mac'])


print_clients_list('10.0.2.1/24')
