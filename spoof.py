import netfilterqueue
from scapy.all import *

def processPacket(packet):
    #print(packet)
#    scapy_packet = IP(packet.get_payload())
    pkt = IP(packet.get_payload())
    #print(pkt.show())
    if not pkt.haslayer(TCP):
        print('NO TCP')
        packet.accept()
    else:
        print('TCP')
        payload = 'TEST'
        if pkt.getlayer(IP).dst == '192.168.164.140':
            print("HIHI123")
            spoofed_pkt = IP(dst=pkt[IP].dst, src=pkt[IP].src /\
                TCP(dport=pkt[TCP].dport, sport=pkt[TCP].sport))
            #print(spoofed_pkt)
            packet.accept
        else:
            packet.accept
    #    print(scapy_packet.show())

    #packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processPacket)
queue.run()