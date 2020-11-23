#!/usr/bin/env python3

import scapy.all as scapy
import optparse


def get_parser():
    parser=optparse.OptionParser()
    parser.add_option("-i","--ip_range",dest="ip",help="Specify ip range for eg: 192.168.0.102 , 192.168.0.1/24")
    opt,arg=parser.parse_args()
    if not opt.ip:
        parser.error("[-] Please Specify an ip range,--help for more info.")
    return opt.ip


def scan(ip):
    arp_req=scapy.ARP(pdst=ip)
    # arp_req.show()
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_req_brod=broadcast/arp_req
    answered=scapy.srp(arp_req_brod,timeout=1,verbose=False)[0]
    print('\n  THIS SCANNER WAS FULLY MADE BY UB THE BEAST :)\n')
    print("IP ADDRESS\t\t\tMAC ADDRESS\n_________________________________________________\n")
    for ele in answered:
        # print(ele)
        print(ele[1].psrc+"\t\t"+ele[1].hwsrc)
    # scapy.ls(scapy.ARP()) #shows the fields we can set
    # print(arp_req.summary())


scan(get_parser())
