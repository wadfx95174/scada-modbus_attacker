import netfilterqueue
from scapy.all import *

def processPacket(packet):
    print(packet)
    scapy_packet = IP(packet.get_payload())
    #print(scapy_packet.show())
    if (scapy_packet.getlayer(IP).dst == '192.168.164.140'):
        print('DST 192.168.164.140')
        if (scapy_packet.getlayer(TCP).flags=='PA'):
            print('Send Back')
            print(scapy_packet.show())
            #scapy_packet[TCP].payload = str(scapy_packet[TCP].payload).replace('\x00','\xFF')
            #scapy_packet[IP].ttl = 100
            #scapy_packet[Raw].load =''
            #del scapy_packet[IP].chksum
            #print(scapy_packet.show())
            #scapy_packet.accept()
            print('?')
        packet.accept()
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processPacket)
queue.run()