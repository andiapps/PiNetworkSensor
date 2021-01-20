import time
import sys
import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11
from os import *
#import schedule
import collections
from collections import Counter
import pandas as pd

deviceList = []
dFrame = []
repeatedDev = []

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
        #if pkt.type == 0:
            #and pkt.subtype == 4:
            #if pkt.addr2 not in deviceList:
                print('Pkt type: ', pkt.type, 'Pkt subtype: ', pkt.subtype)
                deviceList.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
                # print("SSID: %s MAC addr: %s " %(pkt.info, pkt.addr2))

# Packet handler not in use for now
def refPktHandler(pkt):
    if pkt.haslayer(Dot11):
            if pkt.addr2 not in refList:
                refList.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')))
                # print("SSID: %s MAC addr: %s " %(pkt.info, pkt.addr2))

#schedule.every().day.at("20:54").do(sniff, iface=args.iface, prn=refPktHandler, timeout=args.refEpoch)
#while len(refList) == 0:
#    schedule.run_pending()
#print('Ref list: ', refList)
####################Data anonymization on the fly###################
for i in range(args.numOfEp):
    print("This is epoch: " + str(i))
    sniff(iface=args.iface, prn=PacketHandler, timeout=args.epoch)

df = pd.DataFrame(deviceList)
df.to_csv('MAC.csv', encoding='utf-8')
print 'Whole list', deviceList

