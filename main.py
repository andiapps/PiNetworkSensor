import csv
import pandas as pd
import math
import time
from scapy.all import *
from random import randrange

recipients_mac_adress= 'ff:ff:ff:ff:ff:ff'
your_mac_adress= 'aa:bb:cc:dd:ee:ff'
ssid = 'testAP'
channel = chr(11)
interface = 'wlxd037457d5f14'
fc=0
probeNodeDic = {}

processedDf = pd.read_csv('/Users/andywang/Desktop/pbs.csv')
#print(processedDf)

def probeGen(rd):
    #generate probe from last position to current position
    #id of per person
    probePkt = RadioTap() \
               / Dot11(type=0, subtype=4, FCfield=fc, addr1=recipients_mac_adress, addr2=rd,
                       addr3=recipients_mac_adress) \
               / Dot11ProbeReq() / Dot11Elt(ID='SSID', info=ssid) / Dot11Elt(ID='Rates',
                                                                             info='\x82\x84\x8b\x96\x0c\x12\x18') / Dot11Elt(
        ID='DSset', info=channel)
    sendp(probePkt, iface=interface)
    print("end of probe generation")

#Function for generating dictionary which contains key:node ID, value:unique MAC
def dicGen():
    probes = []
    macAdd = 'aa:bb:cc:dd:ee:'
    #Pulls column 'node' from the input csv file and only keep unique values
    keys = processedDf.node.unique()
    for x in keys:
        #each MAC address consists of 6 elements. In this case the last element is customised by using a random num
        p = macAdd + str(randrange(100))
        probes.append(p)
    return dict(zip(keys, probes))

def main():
    senderTimeList = list(processedDf.to_records(index=False))
    timeStart = 0
    pDic = dicGen()
    print(pDic)
    for i in senderTimeList:
        #Assign the pre-generated unique MAC to the node if current node's ID matches with the ID in dictionary
        for id, mac in pDic.items():
            if i[1] == id:
                time.sleep(abs(i[0] - timeStart))
                print('slept for:::', abs(i[0] - timeStart))
                probeGen(mac)

if __name__ == "__main__":
    main()
