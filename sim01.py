import csv
import pandas as pd
import math
import time
from datetime import datetime
import schedule
from schedule import *
from scapy.all import *
from random import randrange

recipients_mac_adress= 'ff:ff:ff:ff:ff:ff'
your_mac_adress= 'aa:bb:cc:dd:ee:ff'
ssid = 'testAP'
channel = chr(11)
interface = 'wlxd037457d5f14'
fc=0

apX = 100
apY = 100
tempCalRow = []
with open('/Users/andywang/Desktop/testFix.csv','r') as inputData:
    reader = csv.DictReader(inputData)
    for row in reader:
        x = float(row['x'])
        y = float(row['y'])
        t = float(row['time'])
        node = int(row['node'])
        para1 = math.sqrt((apX - x) ** 2 + (apY - y) ** 2)
        tempCalRow.append(para1)

originDf = pd.read_csv('/Users/andywang/Desktop/testFix.csv')
originDf['x'] = originDf['x'].astype(float)
originDf['y'] = originDf['y'].astype(float)
originDf['POSdiff'] = tempCalRow
#print(originDf)
inRangeDf = originDf[originDf.POSdiff < 25]
#print(inRangeDf)

countPOSdiff = inRangeDf.node.value_counts()
nDf = inRangeDf[inRangeDf.node.isin(countPOSdiff.index[countPOSdiff.gt(1)])]
timeDiffDf = nDf[['node', 'time']].copy()

timeDiffDf['D'] = timeDiffDf.groupby('node')['time'].diff(-1) * (-1)

rt = timeDiffDf.dropna()
resultNodeTimeLis = list(rt.to_records(index=False))
print('this is node list', resultNodeTimeLis)

def probeTimeTableGenator(inputTupleList):
    x4 = 2
    x2 = 1
    totalTimes = [int(l[x4]/5) for l in inputTupleList]
    t = [l[x2] for l in resultNodeTimeLis]
    timeTableTuple = list(zip(t,totalTimes))
    return timeTableTuple

probeTTableTups = probeTimeTableGenator(resultNodeTimeLis)
print('Probe tuples here', probeTTableTups)


def probeGen():
    #specifiy
    #generate probe from last position to current position
    x = randrange(30) #id of per person
    srcMac = 'aa:bb:cc:dd:ee:' + str(x)
    probePkt = RadioTap() \
               / Dot11(type=0, subtype=4, FCfield=fc, addr1=recipients_mac_adress, addr2=srcMac,
                       addr3=recipients_mac_adress) \
               / Dot11ProbeReq() / Dot11Elt(ID='SSID', info=ssid) / Dot11Elt(ID='Rates',
                                                                             info='\x82\x84\x8b\x96\x0c\x12\x18') / Dot11Elt(
        ID='DSset', info=channel)
    sendp(probePkt, iface=interface, inter=5)
    print("end of probe generation")

nodeTimeList = [l[0] for l in probeTTableTups]
for nt in nodeTimeList:
    for _ in range(probeTTableTups[0][1]): #include node ID 
        if nt == datetime.now().timestamp(): #order the tups according to timestamps
            schedule.every().day.at(nt).do(probeGen)


