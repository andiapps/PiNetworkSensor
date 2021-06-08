import pandas as pd
import math
import operator
import csv
from scapy.all import *
from random import randrange
import time

df=pd.read_csv('test.csv',header='infer',delimiter=' ')
print(df)
# AP coordinates
apX=100; apY=100
#AP transmission range. Set to 75
apRange=50
# access point probe sending rate
t=5
inRangeNods=[] #This is the list with the nodes within the range of c
for i in range(0,len(df)):
    Euclidean_distance=math.sqrt((df.iat[i,2] - apX) ** 2 + (df.iat[i, 3] - apY) ** 2)
    if Euclidean_distance <= apRange:
        inRangeNods.append([df.iat[i, 0], df.iat[i, 1], 'detected_in_range', df.iat[i, 2], df.iat[i, 3]])

#b1. Compute the time it took for the node to reach (x[i],y[i]) from (x[i-1],y[i-1]), which is equal to D = time[i] - time[i-1], expressed in seconds
F=[]
for i in range(0, len(inRangeNods) - 1):
    if inRangeNods[i][0]==inRangeNods[i + 1][0] and inRangeNods[i][2]== 'detected_in_range' and inRangeNods[i + 1][2]== 'detected_in_range':
        D = inRangeNods[i + 1][1] - inRangeNods[i][1]
        no_of_probes=int(D/t)
        #b2.Generate in total D / t = D / 5 tuples of the form < T, node - id > with T = time[i-1], time[i-1] + 5, time[i-1] + 10, ...., time[i]:
        #b3. Append each tuple to a file F.
        for j in range(0,no_of_probes):
            F.append([inRangeNods[i][1] + j * t, inRangeNods[i][0]]) #Time and calcuate the next t time stamps
    if inRangeNods[i][0]==inRangeNods[i + 1][0] and inRangeNods[i][2]== 'detected_in_range' and inRangeNods[i + 1][2]== 'not_detected_out_of_range':
        F.append([inRangeNods[i][1], inRangeNods[i][0]])
#print('File F',F)
#6. Sort F by increasing time, leading to a file F* with time-ordered tuples <T, node-id>
F_sorted = sorted(F, key = operator.itemgetter(0))
print('File F*',F_sorted)

#Generating CSV
fields=['time','node']
with open('input.csv', 'w', newline="") as f:
    # using csv.writer method from CSV package
    write = csv.writer(f)
    write.writerow(fields)
    write.writerows(F_sorted)

###################################################################
recipients_mac_adress= 'ff:ff:ff:ff:ff:ff'
your_mac_adress= 'aa:bb:cc:dd:ee:ff'
ssid = 'testAP'
channel = chr(11)
interface = 'wlxd037457d5f14'
fc=0
probeNodeDic = {}

processedDf = pd.read_csv('input.csv')
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
                timeStart = 0

if __name__ == "__main__":
    main()

