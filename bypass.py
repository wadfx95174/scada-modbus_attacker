import netfilterqueue
from scapy.all import *

def processPacket(packet):
    packet.accept()
    #packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processPacket)
queue.run()