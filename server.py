import zmq
import time
import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11
import pandas as pd
import pandas_zmq


context = zmq.Context()
socket = context.socket(zmq.PUB)
socket.bind("tcp://*:5555")

deviceList = []
dFrame = []

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 4:
            if pkt.addr2 not in deviceList:
                #deviceList.append(pkt.addr2)
                #print("SSID: %s MAC addr: %s " %(pkt.info, pkt.addr2))
                dFrame.append(pkt.addr2)
                df = pd.DataFrame(dFrame, columns = ['MAC address'])
                pandas_zmq.send_dataframe(socket, df)
                return str(pkt.info), str(pkt.addr2)
                
                
while True:
    time.sleep(1)
    sniff(iface = "wlan0", prn = PacketHandler)   
    #msg = sniff
    #socket.send(msg)
    time.sleep(5)
    print("End of epoch")    