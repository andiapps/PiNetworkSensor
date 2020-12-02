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
                deviceList.append(pkt.addr2)
                #print("SSID: %s MAC addr: %s " %(pkt.info, pkt.addr2))
                dFrame.append(pkt.addr2)
                #df = pd.DataFrame(dFrame, columns = ['MAC address'])
                #pandas_zmq.send_dataframe(socket, df)
                #print(deviceList)
                #return str(pkt.info), str(pkt.addr2)
                
               
epoch = time.time() + 60   #set a fixed epoch length for detection
while time.time() <= epoch:
    sniff(iface = "wlan0", prn = PacketHandler)
    df = pd.DataFrame(dFrame, columns = ['MAC address']) 
    concatList = []
    concatList.append(df)       #concatenate each data row to one dataframe
    dfSum = pd.concat(concatList)
    pandas_zmq.send_dataframe(socket, dfSum)    #send the concatenated dataframe through socket
    print(dfSum)
