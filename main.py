from logging import getLogger
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from tabulate import tabulate


print("------SCAPY PORT SCANNER------")

def is_up(ip):
    icmp=IP(dst=ip)/ICMP()
    resp=sr1(icmp,timeout=10)
    if resp==None:
        getLogger("Server is Down")
        print("Server is Down")
        return False
    else:
        getLogger("Server is Up an Running")
        print("Server is Up")
        return True


def sendPacket(pkt):
    if pkt:
     if pkt.haslayer(TCP):
        tcp_layer = pkt.getlayer(TCP)
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")
        print(f"Flags: {tcp_layer.flags}")
        print(f"Sequence Number: {tcp_layer.seq}")
        print(f"Acknowledgment Number: {tcp_layer.ack}")

     if pkt.haslayer(IP):
        ip_layer = pkt.getlayer(IP)
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"TTL: {ip_layer.ttl}")
    else:
     print("No response received.")

def sendRequest():
    userinput2=input("Enter Target IP Address")
    userinput3=int(input("Enter Port Number"))
    return sr1(IP(dst=userinput2)/TCP(dport=userinput3,flags="S"), timeout=4, verbose=0)

sendPacket(sendRequest())

data = [
    ["Source Port", 8989],
    ["Destination Port", 20],
    ["Flags", "RA"],
    ["Sequence Number", 0],
    ["Acknowledgment Number", 1],
    ["Source IP", "45.79.112.203"],
    ["Destination IP", "192.168.8.152"],
    ["TTL", 42]
]
# Display the table
print(tabulate(data, headers=["Field", "Value"], tablefmt="plain"))
