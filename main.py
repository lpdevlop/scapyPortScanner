from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from tabulate import tabulate


print("-------------- SCAPY PORT SCANNER --------------")
print("""
     Select an Option:
     
     1. Scan a Specific IP Address with a Specific Port
     2. Scan an IP Address with a Range of Ports
     """)
print("------------------------------------------------")


def is_ip_reachable(ip):
    icmp_packet = IP(dst=ip)/ICMP()
    response = sr1(icmp_packet, timeout=5, verbose=0)
    if response:
        return True
    else:
        return False

def sendRequest():
    userinput=input("Type:")
    if userinput=="1":
       ipaddress=input("Enter Target IP Address")
       if is_ip_reachable(ipaddress):
          userinput3=int(input("Enter Target Port Number"))
          return open_port(ipaddress,userinput3)
       else:
           print("IP IS Not Reachable")
           return False
    if userinput=="2":
       ipaddress=input("Enter Target IP Address")
       if is_ip_reachable(ipaddress):
           minport=int(input("Enter Min Port Number"))
           maxport=int(input("Enter Max Port Number"))
           return list_open_ports(ipaddress,minport,maxport)
       else:
           print("IP IS Not Reachable")
           return False
    else:
       return False

def open_port(ipaddress, port):
    port_status={}
    pkt = sr1(IP(dst=ipaddress)/TCP(dport=port, flags="S"), timeout=4, verbose=0)
    if pkt and pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer.flags == "SA":
                port_status[port] = "Port Open"
            elif tcp_layer.flags == "RA":
                port_status[port] = "Port Close"
    else:
        port_status[port] = "Port Close"
    return port_status

def list_open_ports(ip,minport,maxport):
    port_status = {}
    for port in range(minport, maxport+1):
        pkt = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=4, verbose=0)
        if pkt and pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer.flags == "SA":
               port_status[port] = "Port Open"
            else:
                port_status[port] = "Port Close"
    return port_status




datalist=sendRequest()
data = [[port, status] for port, status in datalist.items()]

print(tabulate(data,headers=["Port","Status"], tablefmt="orgtbl"))

