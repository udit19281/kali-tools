import scapy.all as scapy
from scapy.layers import http
from colorama import init,Fore


init()

gre=Fore.GREEN
red=Fore.RED
res=Fore.RESET


def sniffer(interface):
    scapy.sniff(iface=interface, store=False,prn=process_sniff_packet)


def process_sniff_packet(packet):
    print(packet)
    # if packet.haslayer(http.HTTPRequest):
    #     print(packet)
        # url=packet[HTTPRequest].Host.decode()+packet[HTTPRequest].Path.decode()
        # ip=packet["10.0.2.6"].scr
        # method=packet[HTTPRequest].Method.decode()
        # # print(f"\n{red}[+] {ip} Requested {url} with {method}{res}")
        # print("\n[+] "+ip+" Requested "+url+" with " + method)


sniffer("eth0")