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
bufferNodeRow = []
with open('/Users/andywang/Desktop/testFix.csv','r') as inputData:
    reader = csv.DictReader(inputData)
    for row in reader:
        x = float(row['x'])
        y = float(row['y'])
        t = float(row['time'])
        node = int(row['node'])
        para1 = math.sqrt((apX - x) ** 2 + (apY - y) ** 2)
        #extract the calculation results(nodes within AP range) to empty list bufferNodeRow
        bufferNodeRow.append(para1)

#Rule out nodes outside of the AP range
originDf = pd.read_csv('/Users/andywang/Desktop/testFix.csv')
originDf['x'] = originDf['x'].astype(float)
originDf['y'] = originDf['y'].astype(float)
#POSdiff refers to the position changing for each node. Used to filter out nodes which are outside of range 25
originDf['POSdiff'] = bufferNodeRow
inRangeDf = originDf[originDf.POSdiff < 25]
inRangeDf = inRangeDf.sort_values(["time"], ascending=True)  #Sort nodes timetable in ascending order
#print(inRangeDf)

countPOSdiff = inRangeDf.node.value_counts()
nDf = inRangeDf[inRangeDf.node.isin(countPOSdiff.index[countPOSdiff.gt(1)])]
timeDiffDf = nDf[['node', 'time']].copy()
timeDiffDf['D'] = timeDiffDf.groupby('node')['time'].diff(-1) * (-1)
rt = timeDiffDf.dropna()
print(rt)

def probeTimeTableGenator(inputTupleList):
    x1 = 2
    x2 = 1
    x3 = 0
    # Calculate the value of D/t where t = 5
    totalTimes = [int(l[x1] / 5) for l in inputTupleList]
    t = [l[x2] for l in inputTupleList]
    nodeID = [l[x3] for l in inputTupleList]
    timeTableTuple = list(zip(nodeID, t, totalTimes))
    return timeTableTuple

def probeGen(rd):
    #specifiy
    #generate probe from last position to current position
     #id of per person
    srcMac = 'aa:bb:cc:dd:ee:' + str(rd)
    probePkt = RadioTap() \
               / Dot11(type=0, subtype=4, FCfield=fc, addr1=recipients_mac_adress, addr2=srcMac,
                       addr3=recipients_mac_adress) \
               / Dot11ProbeReq() / Dot11Elt(ID='SSID', info=ssid) / Dot11Elt(ID='Rates',
                                                                             info='\x82\x84\x8b\x96\x0c\x12\x18') / Dot11Elt(
        ID='DSset', info=channel)
    sendp(probePkt, iface=interface)
    print("end of probe generation")

def sendNodeProbes(nodeTup):
    idLis = [idItem[0] for idItem in nodeTup]
    randNum = randrange(30)
    sleepTLis = [tDiff[2] for tDiff in nodeTup]
    for i in sleepTLis:
            time.sleep(i)
            print('sleeped for::::::::::', i)
            probeGen(randNum)
            print('Sending 1 probe')
            #i refers to the time difference between two nodes. Each new node ID will introduce a time difference bigger than 300 (as in T0 - 0)
            if i > 300:
                randNum = randrange(30)
                probeGen(randNum)
            #probeGen(randNum)

def main():
    tempList = []
    #transform previously created dataframe to tuple list
    resultNodeTimeLis = list(rt.to_records(index=False))
    #print('this is node list', resultNodeTimeLis)
    probeTTableTups = probeTimeTableGenator(resultNodeTimeLis) #create list of tuple consists of ID, time and D
    print('this is probeTTableTups',probeTTableTups)
    df = pd.DataFrame(probeTTableTups, columns=['ID','Time','D'])
    df2 = df.loc[df.index.repeat(df.D)]
    #calculate the timestamps of each node with 5 seconds' gap
    df2['Time'] = df2.groupby(level=0).cumcount() * 5 + df2['Time']
    #calculate the time difference between two nodes' timestamp and add a new column
    df2['TimeDiff'] = df2['Time'] - df2['Time'].shift(1)
    df2['TimeDiff'].fillna(df2['Time'][0] - 0, inplace=True)
    df2 = df2.drop('D', 1)
    #print(df2)
    # transfer dataframe with continious timestamps to list of tuples
    senderTimeList = list(df2.to_records(index=False))
    tempList.append(senderTimeList)
    #print('::::::',tempList)
    for i in tempList:
        sendNodeProbes(i)


if __name__ == "__main__":
    main()