import time
import datetime as dt
import sys
import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11
from os import *
import collections
from collections import Counter
import pandas as pd
import numpy as np
import threading
import multiprocessing as mp
import copy

manager = mp.Manager()
allType2List = manager.list()           #list for saving white list MACs
bufferList = manager.list()             #Array for saving check list MACs

sem1 = threading.Semaphore(1)
sem2 = threading.Semaphore(0)
#================================ Commandline parameters ========================================
parser = argparse.ArgumentParser(
    description="Please enter the wifi interface name(In monitor mode), epoch length(in seconds), white list length and desired number of runs")
parser.add_argument('iface', type=str, help='Monitor mode wifi card name')
#parser.add_argument('refEpoch', type=int, help='Length of reference epoch')
parser.add_argument('epoch', type=int, help='Length of each epoch')
parser.add_argument('wlepoch', type=int, help='length of white list collecting')
parser.add_argument('numOfEp', type=int, help='Desired number of runs')
parser.add_argument('totalEp', type=int, help='Desired number of total run loops')
args = parser.parse_args()

# Packet handler for storing white list
def PacketHandler(pkt):
    if pkt.haslayer(Dot11) and pkt.addr2 != None:
            allType2List.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
# Packet handler for storing check list
def BufferHandler(pkt):
    if pkt.haslayer(Dot11) and pkt.addr2 != None:
            bufferList.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
#================================ White and check list creating functions ===========================
def staticCreator():
    print('Running static')
    sniff(iface=args.iface, prn=PacketHandler, timeout=args.wlepoch)

def checkCreator(eps):
    for _ in range(eps):
        sem1.acquire()
        print('this is bufffff', bufferList)
        print('==============Creating checklist=======')
        sniff(iface=args.iface, prn=BufferHandler, timeout=args.epoch)
        sem2.release()
        
#================Cleaner function for removing MACs haven't been detected for longer than 1 hour======
def checkCleaner(eps):
    appended_data = []
    for _ in range(eps):
            sem2.acquire()
            print('=========Running Cleaning process=======')
            tempCheck = np.asarray(bufferList)
            check = copy.deepcopy(tempCheck)
            #clean up the buffer list ,remove all elements. fresh buffer for each sniffer
            del bufferList[:]
            sem1.release()
            dfCheckList = pd.DataFrame(check)
            dfCheckList.columns = ['MAC', 'TIME']
            dfCheckList['TIME'] = dfCheckList['TIME'].apply(pd.to_datetime)
            dfCheckList.drop_duplicates('MAC', keep='last', inplace=True)
            dfCheckList['diff'] = (pd.Timestamp.now().normalize() - dfCheckList['TIME']).abs().dt.total_seconds() / 60.0
            #Remove MACs which haven't been detected for more than 1 hour
            dfCheckList.drop( dfCheckList[dfCheckList['diff'] > 3600 ].index, inplace=True)
            appended_data.append(dfCheckList)
    appended_data = pd.concat(appended_data)
    appended_data.to_csv('cleanedList.csv', encoding='utf-8', index=True)
                       
# Creating static list first
staticCreator()
sharedArr = np.asarray(allType2List)
#Processing white list with pandas
dfWhiteList = pd.DataFrame(sharedArr)
dfWhiteList.columns = ['MAC', 'TIME']
dfWhiteList['TIME'] = dfWhiteList['TIME'].apply(pd.to_datetime)
dfWhiteList.drop_duplicates('MAC', keep='last', inplace=True)
dfWhiteList.reset_index(drop=True, inplace=True)
dfWhiteList.to_csv('whiteList.csv', encoding='utf-8', index=True)

#Update the white list at the end
def wlUpdate():
    dfCleanedCL = pd.read_csv('cleanedList.csv')
    finalWhiteList = dfWhiteList[dfWhiteList.MAC.isin(dfCleanedCL.MAC)]
    finalWhiteList.reset_index(drop=True, inplace=True)
    finalWhiteList.to_csv('finalOutput.csv', encoding='utf-8', index=True )

#Creating checklist while running cleaning function at the same time
#"totalLoops" also defines the time interval between white list updates. eg. epoch = 20, eps = 2,
#the gap between two updates is 20 X 2 = 40 seconds
totalLoops = args.totalEp
for _ in range(totalLoops):
    eps = args.numOfEp
    creator = threading.Thread(target=checkCreator, args=(eps,))
    cleaner = threading.Thread(target=checkCleaner, args=(eps,))
    creator.start()
    cleaner.start()
    cleaner.join()
    creator.join()
    
    wlUpdate()
