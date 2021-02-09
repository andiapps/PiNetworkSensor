import time
import sys
import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11
from os import *
import schedule
import collections
from collections import Counter
import pandas as pd

allType2List = []

dFrame = []
repeatedDev = []
bufferList = []

parser = argparse.ArgumentParser(
    description="Please enter the wifi interface name(In monitor mode), reference epoch length, epoch length(in seconds) and desired number of runs")
parser.add_argument('iface', type=str, help='Monitor mode wifi card name')
#parser.add_argument('refEpoch', type=int, help='Length of reference epoch')
parser.add_argument('epoch', type=int, help='Length of each epoch')
parser.add_argument('numOfEp', type=int, help='Desired number of runs')
args = parser.parse_args()

###################Package sniffing function###################

# The only packet sniffing handler in use for now
def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
            if pkt.type == 0:
                allType2List.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
            if pkt.type == 1 and pkt.addr2 != None:
                allType2List.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
            if pkt.type == 2 and pkt.addr2 != None:
                allType2List.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
            if pkt.type == 3 and pkt.addr2 != None:
                allType2List.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
                # print("SSID: %s MAC addr: %s " %(pkt.info, pkt.addr2))

def BufferHandler(pkt):
    if pkt.haslayer(Dot11):
            if pkt.type == 0:
                bufferList.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
            if pkt.type == 1 and pkt.addr2 != None:
                bufferList.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
            if pkt.type == 2 and pkt.addr2 != None:
                bufferList.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
            if pkt.type == 3 and pkt.addr2 != None:
                bufferList.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))

####################Data Processing##########################
schedule.every().day.at("01:12").do(sniff, iface=args.iface, prn=PacketHandler, timeout=1500)
while len(allType2List) == 0:
    schedule.run_pending()
print('Ref list: ', allType2List)
time.sleep(15)

for i in range(args.numOfEp):
    print("This is epoch: " + str(i))
    sniff(iface=args.iface, prn=BufferHandler, timeout=args.epoch)

dfWhiteList = pd.DataFrame(allType2List)
dfWhiteList.columns = ['MAC', 'Time']
dfWhiteList.drop_duplicates('MAC', keep='first', inplace=True)

dfBufferList = pd.DataFrame(bufferList)
dfBufferList.columns = ['MAC', 'Time']
dfBufferList.drop_duplicates('MAC', keep='first', inplace=True)
#Option for selecting top x most appearing addresses
#topWhiteList = dfWhiteList['MAC'].value_counts()[0:5]
#missingDevices = dfWhiteList.loc[dfWhiteList['MAC'].isin(dfBufferList)]
#missingDevices.columns=['MAC','Time']
#missingDevices.drop_duplicates('MAC',keep='first',inplace=True)
#stationDev = dfWhiteList.drop(dfWhiteList[missingDevices].index, inplace=True)
listTable = dfWhiteList.assign(Missing=dfWhiteList.MAC.isin(dfBufferList.MAC).astype(int))
print listTable

