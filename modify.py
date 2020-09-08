import netfilterqueue
from scapy.all import *

def processPacket(packet):
    
    pkt = IP(packet.get_payload())
    if (pkt.haslayer(TCP) and pkt[TCP].flags=='PA' and pkt.getlayer(IP).dst == '192.168.164.140'):
        print('+')
        print (pkt[Raw].load)
        #pkt[Raw].load = ''
        #pkt[Raw].load = pkt[Raw].load.replace(b'x84B',b'x84A')
        pkt[Raw].load =b'\x01\x02\x00\x00\x00\x0b\x01\x04\x08\x02\x0b\x19\xbb\x1e\x04\x00\x00'
        #print (pkt[Raw].load)
        print('-')
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum
        # packet.set_payload(bytes(pkt))
        print('pkt================================')
        print (pkt.show())
        print('packet==================================')
        print (IP(packet.get_payload()).show())
        print('====================================')
    packet.accept()
    #packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processPacket)
queue.run()