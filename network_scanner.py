#!/usr/bin/env python3

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',
                        help='Range of IP targets (ex. 10.1.1.1/24).')
    (arguments) = parser.parse_args()

    if not arguments.target:
        parser.error('[-] Please specify a target (-t, --target).')
    return arguments


def get_arp_request(target):
    scapy.ls(scapy.ARP())
    return scapy.ARP(pdst=target)


def get_broadcast():
    return scapy.Ether(dst='ff:ff:ff:ff:ff:ff')


def get_clients_list(target):
    clients_list = []
    arp_request = get_arp_request(target)
    broadcast = get_broadcast()
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]

    for answer in answered_list:
        client_dict = {'target': answer[1].psrc, 'mac': answer[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_clients_list():
    arguments = get_arguments()
    clients_list = get_clients_list(arguments.target)

    print('Target IP\tMAC Address\n----------------------------------')

    for client in clients_list:
        print(client['target'] + '\t' + client['mac'])


print_clients_list()
