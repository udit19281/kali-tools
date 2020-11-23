#!/usr/bin/env python3

import subprocess as s
import optparse
import re


def get_parser():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address")
    parser.add_option("-m", "--mac", dest="mac", help="new MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an Interface ,--help for more info.")
    elif not options.mac:
        parser.error("[-] Please specify a MAC Address ,--help for more info.")
    return options


def change_mac(interface,mac):
    # print("[+] Changing MAC address of "+interface+" to "+mac)
    s.call(["ifconfig",interface,"down"])
    s.call(["ifconfig",interface,"hw","ether",mac])
    s.call(["ifconfig",interface,"up"])


def current_mac(interface):
    out=s.check_output(["ifconfig "+interface],shell=True).decode("utf-8")
    cur=re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",out)
    if cur:
        print("Current MAC Address : "+str(cur.group(0)))
        return cur.group(0)
    else:
        print("[-} Could not load Current MAC Address")


options=get_parser()
current_mac(options.interface)
change_mac(options.interface,options.mac)
c=current_mac(options.interface)
if c==options.mac:
    print("[+] MAC Address was Successfully Changed to\t:"+c+"\t:"+options.interface)
else:
    print("[-] MAC Address could not be changed. ")

