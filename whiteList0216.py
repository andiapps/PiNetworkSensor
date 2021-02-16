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
from threading import Timer
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

def checkListBuilder(numEps, lenEps):
    for i in range(numEps):
        print("This is epoch: " + str(i))
        sniff(iface=args.iface, prn=BufferHandler, timeout=lenEps)
        #Do something here to compare data with white list
        dfCheckList = pd.DataFrame(bufferList)
        dfCheckList.columns = ['MAC', 'TIME']
    dfCheckList.to_csv('checkList.csv', encoding='utf-8', index=True)
#def findMobile():
    #compare timestamps and find out MACs to remove
    
####################Data Processing##########################
for i in range(5):
    print("This is epoch: " + str(i))
    sniff(iface=args.iface, prn=PacketHandler, timeout=10)
    sniff(iface=args.iface, prn=BufferHandler, timeout=10)
dfWhiteList = pd.DataFrame(allType2List)
dfWhiteList.columns = ['MAC', 'TIME']
dfWhiteList.to_csv('whiteList.csv', encoding='utf-8', index=True)
print '\n ===================================================================================='
#print 'WHITELIST: ', allType2List
#print 'CHECK LIST: ', bufferList
checkListBuilder(args.numOfEp, args.epoch)


